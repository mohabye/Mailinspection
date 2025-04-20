MailInspector - Advanced Email Threat Analysis Tool
MailInspector is a powerful and versatile email analysis tool designed for cybersecurity professionals, security analysts, and incident response teams. It streamlines the process of extracting and analyzing email data to detect phishing attempts, malicious attachments, and harmful URLs. By providing comprehensive insights into email metadata, sender reputation, and indicators of compromise (IOCs), MailInspector is an indispensable resource for investigating email-based threats.

🚀 Features
1. Comprehensive Email Metadata Analysis
Extracts critical metadata, such as:
Sender email address, domain, and IP address.
Recipient and reply-to details.
Headers for SPF, DKIM, and DMARC authentication checks.
Assesses the legitimacy of email senders and their associated infrastructure.

3. URL Extraction and Threat Assessment
Detects and extracts embedded URLs.
Integrates with the VirusTotal API to evaluate URL reputation and safety.
Flags phishing links and domains tied to malware.

5. Attachment Extraction and Handling
Saves all attachments locally for further analysis.
Enables manual or automated malware analysis using external tools.

7. Domain and IP Reputation Checks
Performs domain analysis with VirusTotal and retrieves WHOIS data, including:
Registration details, creation, and expiration dates.
Verifies sender IP reputation using AbuseIPDB, displaying:
Abuse confidence scores, report counts, and geolocation data.

9. Suspicious Subject Detection
Scans email subjects for keywords linked to phishing or fraud (e.g., "urgent," "invoice").
Highlights suspicious phrases for prioritization.

11. Flexible Email File Parsing
Supports .eml file format for single and multi-part email structures.
Analyzes plain-text and HTML email bodies.

13. Real-Time Report Generation
Outputs a detailed summary, including:
Sender metadata and reputation.
URL, domain, IP, and attachment analysis results.
Presents findings in a color-coded, easy-to-read format for rapid triage.
14. Automation-Ready Design
Modular architecture supports integration with larger threat detection workflows.
Fully customizable for organizational needs.

🛠️ How It Works
Input
Users provide a .eml file for analysis. These files may originate from suspicious email reports or incident investigations.

Processing Steps
Email Metadata Extraction
Retrieves sender, recipient, and authentication data.

URL and Attachment Handling

Extracts URLs and assesses their safety using VirusTotal.
Saves email attachments for further manual or automated analysis.
Domain and IP Reputation Checks

WHOIS data and VirusTotal analysis for domains.
AbuseIPDB verification for IP reputation.
Suspicious Content Detection
Scans email subjects for keywords associated with phishing or fraud.

Threat Report Compilation
Produces an actionable report summarizing findings.

Output
The tool provides:

Metadata breakdown.
URL, domain, and IP analysis.
Suspicious attachments and URLs flagged for review.

.
📖 Usage Guide
1. Installation
Ensure Python 3.6+ is installed. Clone this repository and install dependencies:

git clone https://github.com/mohabye/MailInspector.git

cd MailInspector

2. Configuration
Replace Your_API_Here in the script with your VirusTotal and AbuseIPDB API keys.

3. Running the Tool
Launch the tool:

python mailinspector.py
Follow the on-screen instructions to provide the .eml file path.

4. Output Directory
Attachments are saved in the attachments directory. You can customize this path in the script.

🧩 Detailed Functional Overview
Email Metadata Extraction
Extracts sender, domain, and IP details.
Verifies SPF, DKIM, and DMARC authentication.
Retrieves email creation timestamps and routing data.

Domain and IP Intelligence
WHOIS Lookup: Registration dates, domain owner, and organization details.
VirusTotal: Flags malicious domains or IPs.
AbuseIPDB: Provides abuse confidence scores and geolocation.
Attachment Handling
Extracts and prepares attachments for malware analysis.

URL Analysis
Filters and checks URLs against VirusTotal.
Reports malicious URLs with threat intelligence details.
Threat Detection in Subjects
Highlights keywords like "urgent" or "payment" for identifying phishing attempts.

📋 Requirements
Software
Python: Version 3.6 or higher.
Python Libraries
Install via pip:
pip install requests email whois re

API Keys
VirusTotal API: For domain and URL analysis.
AbuseIPDB API: For IP reputation checks.

🌟 Benefits for Security Professionals
Rapid Triage: Automates initial email threat investigation steps.

Comprehensive Insights: Offers metadata, domain, IP, and content analysis in one place.

User-Friendly: Straightforward prompts and color-coded outputs.

Customizable: Adaptable to organizational workflows and needs.

⚠️ Limitations
API Integration: Requires valid API keys for VirusTotal and AbuseIPDB.
Format Scope: Supports .eml files; other formats may require preprocessing.
🔒 Legal and Ethical Usage
MailInspector is intended for legal, authorized use only. Users must comply with applicable laws and obtain necessary permissions before analyzing emails. Misuse may lead to legal consequences.

🚀 Future Enhancements
GUI integration for improved usability.
Support for additional email file formats.
Integration with advanced malware analysis tools.


![image](https://github.com/user-attachments/assets/042ff8e5-27f3-40c4-9242-d4fa3cfa075a)

![image](https://github.com/user-attachments/assets/00b508d7-e161-41c5-a028-83215cae7ae8)




