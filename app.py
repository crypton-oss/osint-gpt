import os
import hashlib
import json
import tempfile
import uuid
from pathlib import Path
from typing import List
import requests

import cachetools
import markdown
from flask import Flask, flash, render_template, request
from vulnerability_assessment import VulnerabilityAssessmentReport

# Langchain importlarini to'g'ridan-to'g'ri community va core'dan chaqiramiz
from langchain_core.documents import Document
from langchain_core.runnables import RunnablePassthrough
from langchain_community.document_loaders import (CSVLoader, UnstructuredHTMLLoader,
                                        UnstructuredMarkdownLoader,
                                        UnstructuredPDFLoader)
from langchain_community.document_loaders.base import BaseLoader
from langchain_community.embeddings import DeterministicFakeEmbedding
from langchain_text_splitters import CharacterTextSplitter
from langchain_community.vectorstores import FAISS
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate

app = Flask(__name__)
app.secret_key = uuid.uuid4().hex

# API Kalitlari
SHODAN_KEY = "68VTv0cYzJRitMgbSNJ2byC8BmkSPM0s"
INTELX_KEY = "4058c15c-2db8-478a-be57-d5f027fde876"
VT_KEY = "ed6830afdb502f00560b8c06a6e961ab05ec31ed49ba68eb4e1df8e3f0ba197f"

# Python 3.14 uchun barqaror embedding
embeddings = DeterministicFakeEmbedding(size=1536) 
text_splitter = CharacterTextSplitter(chunk_size=500, chunk_overlap=50)
index_cache = cachetools.LRUCache(maxsize=100)

# SHODAN API
def search_shodan(query):
    try:
        url = f"https://api.shodan.io/shodan/host/search?query={query}&key={SHODAN_KEY}"
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        return {"error": "Shodan API xatosi", "status": response.status_code}
    except Exception as e:
        return {"error": str(e)}

# IntelX API
def search_intelx(query):
    try:
        url = "https://2.intelx.io/intelligent/search"
        headers = {"User-Agent": "Mozilla/5.0", "x-key": INTELX_KEY}
        data = {"term": query, "buckets": ["ipv4", "domain", "email"], "lookupip": 1}
        response = requests.post(url, json=data, headers=headers, timeout=30)
        if response.status_code == 200:
            return response.json()
        return {"error": "IntelX API xatosi", "status": response.status_code}
    except Exception as e:
        return {"error": str(e)}

# VirusTotal API
def search_virustotal(indicator):
    try:
        # IP yoki domen uchun tekshirish
        if indicator.replace('.', '').isdigit():  # IP
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
        else:  # Domen
            url = f"https://www.virustotal.com/api/v3/domains/{indicator}"
        
        headers = {"x-apikey": VT_KEY}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        return {"error": "VirusTotal API xatosi", "status": response.status_code}
    except Exception as e:
        return {"error": str(e)}

def files_hash_sha256(file_paths):
     sha256_hash = hashlib.sha256()
     for file_path in file_paths:
         with open(file_path, 'rb') as file:
             chunk_size = 8192
             file_chunk = file.read(chunk_size)
             while file_chunk:
                 sha256_hash.update(file_chunk)
                 file_chunk = file.read(chunk_size)
     return sha256_hash.hexdigest()

def concatenate_rows(row: dict) -> str:
    return f"{row['from']} on {row['date']}: {row['text']}\n\n"

def mp(message) -> str:
    if isinstance(message, str):
        return message
    ret = ""
    for x in message:
        if isinstance(x, str):
            ret += x
        elif isinstance(x, dict) and 'text' in x:
            ret += x['text']
    return ret

class TelegramChatLoader(BaseLoader):
    def __init__(self, path: str):
        self.file_path = path

    def load(self) -> List[Document]:
        import pandas as pd
        p = Path(self.file_path)
        with open(p, encoding="utf8") as f:
            d = json.load(f)
        df = pd.json_normalize(d["messages"])
        df_filtered = df[(df.type == "message") & (df.text.apply(mp))]
        df_filtered = df_filtered[["date", "text", "from"]]
        text = df_filtered.apply(concatenate_rows, axis=1).str.cat(sep="")
        return [Document(page_content=text, metadata={"source": str(p)})]

class TelegramScraperLoader(BaseLoader):
    def __init__(self, path: str):
        self.file_path = path

    def load(self) -> List[Document]:
        p = Path(self.file_path)
        with open(p, mode='r') as f:
            data = [json.loads(line) for line in f]
            text = ' '.join([f"date: {obj['date']} text: {obj['content']}" for obj in data])
        return [Document(page_content=text, metadata={"source": str(p)})]

def get_loader(file):
    if file.endswith(".json"): return TelegramChatLoader(file)
    if file.endswith(".jsonl"): return TelegramScraperLoader(file)
    if file.endswith(".html"): return UnstructuredHTMLLoader(file)
    if file.endswith(".csv"): return CSVLoader(file)
    if file.endswith(".pdf"): return UnstructuredPDFLoader(file)
    return UnstructuredMarkdownLoader(file)

def get_completion(files, question):
     f_hash = files_hash_sha256(files)
     if f_hash in index_cache:
         db = index_cache[f_hash]
     else:
         documents = []
         for file in files:
             documents.extend(get_loader(file).load())
         texts = text_splitter.split_documents(documents)
         db = FAISS.from_documents(texts, embeddings)
         index_cache[f_hash] = db
     
     # OSINT API lardan ma'lumotlarni yig'ish
     shodan_data = search_shodan(question)
     intelx_data = search_intelx(question)
     vt_data = search_virustotal(question)
     
     # Vulnerability Assessment Report tayyorlash
     assessor = VulnerabilityAssessmentReport()
     assessment_report = assessor.generate_report(shodan_data, intelx_data, vt_data)
     
     return assessment_report

def process_files(files, question):
    file_paths = []
    temp_dir = tempfile.mkdtemp()
    for file in files:
        file_path = os.path.join(temp_dir, file.filename)
        file.save(file_path)
        file_paths.append(file_path)
    response = get_completion(file_paths, "Context bilan javob ber: " + question)
    return response

@app.route("/", methods=["GET", "POST"])
def upload_files():
    if request.method == "POST":
        try:
            files = request.files.getlist("json_files")
            question = request.form["question"]
            answer = process_files(files, question)
            return render_template("result.html", question=question, answer_html=markdown.markdown(answer))
        except Exception as e:
            flash('Xato: ' + str(e), 'error')
    return render_template("upload.html")

if __name__ == "__main__":
    app.run(debug=True, port=8080)