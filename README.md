MailInspector - Advanced Email Threat Analysis Tool
MailInspector is a robust and feature-rich email analysis tool designed for cybersecurity professionals, security analysts, and incident response teams. The tool automates the process of extracting and analyzing email data, making it easier to identify phishing attempts, malicious attachments, and harmful URLs. It provides comprehensive insights into email metadata, sender reputation, and potential indicators of compromise (IOCs).

Features
1. Comprehensive Email Metadata Analysis
Extracts and analyzes critical email metadata, including:
Sender email address, domain, and IP address.
Recipient and reply-to information.
Headers like SPF, DKIM, and DMARC for email authentication checks.
Provides insights into the legitimacy of email senders and their associated infrastructure.
2. URL Extraction and Threat Assessment
Detects and extracts URLs embedded within email bodies.
Integrates with the VirusTotal API to assess the reputation and safety of URLs.
Identifies phishing links or domains associated with malware.
3. Attachment Extraction and Handling
Extracts all attachments from email files and saves them locally for further analysis.
Enables manual or automated malware analysis using external tools.
4. Domain and IP Reputation Checks
Queries VirusTotal for domain analysis, providing details on malicious indicators and last analysis statistics.
Retrieves WHOIS information for sender domains, including:
Domain creation and expiration dates.
Registered organization and owner details.
Verifies sender IP reputation through AbuseIPDB, displaying:
Number of reports and abuse confidence score.
Associated country and ISP information.
5. Suspicious Subject Detection
Scans email subjects for keywords associated with phishing or fraud (e.g., "urgent," "payment," "invoice").
Highlights suspicious phrases to prioritize further investigation.
6. Flexible Email File Parsing
Supports .eml files, parsing both single-part and multi-part email formats.
Handles plain-text and HTML email bodies for analysis.
7. Real-Time Report Generation
Outputs a detailed summary of:
Sender metadata and reputation findings.
Results of domain, IP, URL, and attachment analysis.
Presents findings in an easy-to-understand, color-coded format for rapid triage.
8. Automation-Ready for Incident Response
Modular design allows for integration into larger threat detection workflows.
Offers flexibility for customization, making it adaptable to specific organizational needs.
How It Works
Input
Users provide an email file (.eml) containing the email to be analyzed. This file may originate from suspicious email reports or as part of an incident investigation.

Processing
Email Metadata Extraction:
Extracts sender/recipient details, authentication headers, and more.
URL and Attachment Handling:
Identifies URLs for VirusTotal checks.
Extracts and saves attachments locally for further examination.
Domain and IP Reputation Checks:
Assesses the sender domain using WHOIS and VirusTotal.
Verifies sender IP reputation through AbuseIPDB.
Suspicious Content Detection:
Flags suspicious email subjects and highlights keywords.
Threat Report Compilation:
Summarizes findings into an actionable report.
Output
The tool provides:

Detailed metadata breakdown.
URL and domain reputation analysis.
IP reputation insights.
List of suspicious attachments and URLs for additional scrutiny.
Usage Guide
1. Installation
Ensure you have Python 3.6+ installed. Clone this repository and install the required Python libraries:

bash
Copy code
git clone https://github.com/YourUsername/MailInspector.git
cd MailInspector
pip install -r requirements.txt
2. Configuration
To use VirusTotal and AbuseIPDB APIs, add your API keys by replacing Your_API_Here in the script with your valid keys. These services enhance the tool’s capabilities by providing reputation and threat intelligence.

3. Running the Tool
Launch the tool from the terminal:

bash
Copy code
python mailinspector.py
Follow the on-screen instructions to specify the .eml file path for analysis. The tool will process the email and display its findings in the terminal.

4. Output Directory
Attachments are saved to a default directory named attachments in the script's root folder. You can modify this directory path as needed.

Detailed Functional Overview
Email Metadata Extraction
MailInspector parses email headers and bodies to extract:

Sender Details: Email address, domain, IP address, and related metadata.
Authentication Results: Checks for SPF, DKIM, and DMARC headers to determine sender legitimacy.
Timestamps: Extracts and displays email creation dates and associated routing timestamps.
Domain and IP Intelligence
The tool integrates with WHOIS, VirusTotal, and AbuseIPDB for detailed domain and IP analysis:

WHOIS Lookup: Provides information about domain registration dates and registered organizations.
VirusTotal Analysis: Highlights any flagged domains or IPs associated with known malicious activity.
AbuseIPDB: Offers insight into IP reputation, abuse reports, and geolocation.
Attachment Handling
MailInspector extracts attachments from emails and prepares them for manual or automated analysis. Use this feature to handle potential malware files effectively.

URL Analysis
All URLs detected in the email body are:

Extracted: Filtered for duplicates and invalid links.
Checked: Submitted to VirusTotal for reputation analysis.
Reported: Summarized with details on malicious findings.
Threat Detection in Email Subjects
Using a list of customizable keywords, MailInspector flags potentially harmful email subjects for quick triage. This is useful for identifying phishing attempts.

Requirements
Software
Python: Version 3.6 or higher.
Python Libraries
Install these via pip:

requests
email
whois
re
API Keys
VirusTotal API: Required for domain and URL analysis.
AbuseIPDB API: Required for IP reputation checks.
Benefits for Security Professionals
Rapid Triage: Automates the initial stages of email threat investigation, saving time.
Comprehensive Insights: Provides metadata, domain, IP, and content analysis in one tool.
Ease of Use: Intuitive prompts and straightforward output format make it accessible for all experience levels.
Customizable: Modify keyword lists, directory paths, or integrate with other tools.
Limitations
Manual API Integration: Requires valid API keys for third-party services like VirusTotal and AbuseIPDB.
Focused Scope: Designed specifically for .eml files; additional formats require preprocessing.
Legal and Ethical Usage
MailInspector is intended for legal and ethical use only. Users must comply with all applicable laws and obtain proper authorization before analyzing emails. Misuse of this tool may result in legal consequences.

Future Enhancements
Planned updates include:

GUI integration for user-friendly interaction.
Support for additional email file formats.
Integration with advanced malware analysis tools.
