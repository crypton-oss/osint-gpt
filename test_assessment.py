#!/usr/bin/env python3
"""
Test script - Vulnerability Assessment Report
"""

from vulnerability_assessment import VulnerabilityAssessmentReport

# Test sample data
sample_shodan_data = {
    "matches": [
        {
            "port": 22,
            "product": "OpenSSH",
            "version": "7.4",
            "org": "Test Organization"
        },
        {
            "port": 3306,
            "product": "MySQL",
            "version": "5.7.30",
            "org": "Test Organization"
        },
        {
            "port": 9200,
            "product": "Elasticsearch",
            "version": "7.0.0",
            "org": "Test Organization"
        }
    ]
}

sample_intelx_data = {
    "records": [
        {
            "type": "email",
            "source": "Breach Database",
            "date": "2024-01-15"
        },
        {
            "type": "password_hash",
            "source": "Dark Web",
            "date": "2024-01-10"
        }
    ]
}

sample_vt_data = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 3,
                "suspicious": 2,
                "undetected": 60
            },
            "last_analysis_date": 1704052800,
            "categories": {
                "Malware": "malicious"
            }
        }
    }
}

if __name__ == "__main__":
    assessor = VulnerabilityAssessmentReport()
    report = assessor.generate_report(sample_shodan_data, sample_intelx_data, sample_vt_data)
    
    print(report)
    
    # Save report to file
    with open("/home/crypton/Desktop/gpt-osint/assessment_report.txt", "w", encoding="utf-8") as f:
        f.write(report)
    
    print("\n✅ Report saved to: assessment_report.txt")
