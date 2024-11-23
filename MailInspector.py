import os
import re
import requests
import hashlib
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
import whois
from os import system


RED, WHITE, YELLOW, CIANO, GREEN, END = '\033[91m', '\033[46m', '\033[93m', '\033[100m', '\033[1;32m', '\033[0m'


def runPEnv():
    system('clear')
    print('''
     __  __       _ _        _____                           _
    |  \/  |     (_) |      |_   _|                         | |
    | \  / | __ _ _| | ___    | |  _ __ ___  _ __ ___   __ _| |_
    | |\/| |/ _` | | |/ _ \   | | | '__/ _ \| '_ ` _ \ / _` | __|
    | |  | | (_| | | |  __/  _| |_| | | (_) | | | | | | (_| | |_
    |_|  |_|\__,_|_|_|\___| |_____|_|  \___/|_| |_| |_|\__,_|\__|

                                                                                   {1}

                        [ {0} MailInspector  {1}|{0}   Unmasking phishing  {1}]\n\n'''.format(RED, END))


def colorize_value(value):
    if isinstance(value, str) and any(s in value.lower() for s in ['none', 'fail', 'not found']):
        return f"{RED}{value}{END}"
    else:
        return value


def print_green(message):
    print(f"{GREEN}{message}{END}")


def check_virustotal_domain(domain):
    api_key = "Your_API_Here"  
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        else:
            return {"error": f"Failed to retrieve data, status code: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def check_virustotal_url(url_to_check):
    api_key = "Your_API_Here"  
    url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": api_key}
    try:
        data = {"url": url_to_check}
        response = requests.post(url, headers=headers, data=data)
        if response.status_code == 200:
            json_response = response.json()
            url_id = json_response["data"]["id"]
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
            analysis_response = requests.get(analysis_url, headers=headers)
            if analysis_response.status_code == 200:
                analysis_data = analysis_response.json()
                stats = analysis_data.get("data", {}).get("attributes", {}).get("stats", {})
                return stats
            else:
                return {"error": f"Failed to retrieve analysis, status code: {analysis_response.status_code}"}
        else:
            return {"error": f"Failed to submit URL, status code: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def get_whois_info(domain):
    try:
        domain_info = whois.whois(domain)
        return {
            "creation_date": domain_info.creation_date,
            "expiration_date": domain_info.expiration_date,
            "organization": domain_info.org,
        }
    except Exception as e:
        return {"error": str(e)}


def check_abuseipdb(ip_address):
    api_key = "Your_API_here"  # Replace with your AbuseIPDB API key
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip_address, "maxAgeInDays": 90}
    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            return response.json().get("data", {})
        else:
            return {"error": f"Failed to retrieve data, status code: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def read_email_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
        return msg
    except Exception as e:
        print(f"An error occurred while reading the email file: {e}")
        return None


def extract_basic_email_details(msg):
    
    sender = msg['From']
    recipient = msg['To']
    reply_to = msg['Reply-To']
    return_path = msg['Return-Path']
    date = msg['Date']
    subject = msg['Subject']
    sender_email, sender_name, sender_domain, sender_ip = None, None, None, "Not found"

    
    if sender:
        match = re.match(r'(.*)<(.*)>', sender)
        if match:
            sender_name = match.group(1).strip()
            sender_email = match.group(2).strip()
        else:
            sender_email = sender.strip()

    
    if sender_email:
        domain_match = re.search(r'@([a-zA-Z0-9.-]+)$', sender_email)
        sender_domain = domain_match.group(1) if domain_match else None

    
    if "X-Sender-IP" in msg:
        sender_ip = msg["X-Sender-IP"].strip()
    elif "X-Originating-IP" in msg:
        origin_match = re.search(r"\[([\d\.]+)\]", msg["X-Originating-IP"])
        if origin_match:
            sender_ip = origin_match.group(1)
    else:
        for header in msg.get_all("Received", []):
            ip_match = re.search(r"\[([\d\.]+)\]", header)
            if ip_match:
                sender_ip = ip_match.group(1)
                break

    
    spf, dmarc, dkim = "Not found in headers", "Not found", "Not found"
    for header in msg.keys():
        if header.lower() == "received-spf":
            spf = msg[header]
        elif header.lower().startswith("authentication-results"):
            auth_results = msg[header]
            if "dmarc=" in auth_results:
                dmarc_match = re.search(r"dmarc=(\w+)", auth_results)
                dmarc = dmarc_match.group(1) if dmarc_match else "Not found"
            if "dkim=" in auth_results:
                dkim_match = re.search(r"dkim=(\w+)", auth_results)
                dkim = dkim_match.group(1) if dkim_match else "Not found"


    email_details = {
        "date": date,
        "sender_name": sender_name,
        "sender_email": sender_email,
        "sender_domain": sender_domain,
        "sender_ip": sender_ip,
        "reply_to": reply_to,
        "return_path": return_path,
        "spf": spf,
        "dmarc": dmarc,
        "dkim": dkim,
        "recipient": recipient,
        "subject": subject,
    }
    return email_details


def print_email_details(details):
    print("\n--- Email Details ---")
    print(f"{GREEN}Date:{END} {colorize_value(details.get('date', 'N/A'))}")
    print(f"{GREEN}Sender Name:{END} {colorize_value(details.get('sender_name', 'N/A'))}")
    print(f"{GREEN}Sender Email:{END} {colorize_value(details.get('sender_email', 'N/A'))}")
    print(f"{GREEN}Sender Domain:{END} {colorize_value(details.get('sender_domain', 'N/A'))}")
    print(f"{GREEN}Sender IP:{END} {colorize_value(details.get('sender_ip', 'Not found'))}")
    print(f"{GREEN}Reply-To:{END} {colorize_value(details.get('reply_to', 'N/A'))}")
    print(f"{GREEN}Return-Path:{END} {colorize_value(details.get('return_path', 'N/A'))}")
    print(f"{GREEN}SPF:{END} {colorize_value(details.get('spf', 'Not found in headers'))}")
    print(f"{GREEN}DMARC:{END} {colorize_value(details.get('dmarc', 'Not found'))}")
    print(f"{GREEN}DKIM:{END} {colorize_value(details.get('dkim', 'Not found'))}")
    print(f"{GREEN}Recipient Email:{END} {colorize_value(details.get('recipient', 'N/A'))}")
    print(f"{GREEN}Subject:{END} {colorize_value(details.get('subject', 'N/A'))}")
    print("----------------------")


def analyze_sender_domain_and_ip(details):
    sender_domain = details.get('sender_domain')
    sender_ip = details.get('sender_ip')

    
    virustotal_domain_results = check_virustotal_domain(sender_domain) if sender_domain else None
    whois_info = get_whois_info(sender_domain) if sender_domain else None

   
    abuseipdb_results = check_abuseipdb(sender_ip) if sender_ip != "Not found" else None

    
    if abuseipdb_results:
        print("\n--- Sender IP Analysis ---")
        if "error" in abuseipdb_results:
            print(f"{GREEN}AbuseIPDB Check:{END} {colorize_value(abuseipdb_results['error'])}")
        else:
            print(f"{GREEN}AbuseIPDB Reported:{END} {colorize_value(abuseipdb_results.get('totalReports', 'N/A'))} times")
            print(f"{GREEN}AbuseIPDB Confidence Score:{END} {colorize_value(abuseipdb_results.get('abuseConfidenceScore', 'N/A'))}")
            print(f"{GREEN}AbuseIPDB Country:{END} {colorize_value(abuseipdb_results.get('countryName', 'N/A'))}")
            print(f"{GREEN}AbuseIPDB ISP:{END} {colorize_value(abuseipdb_results.get('isp', 'N/A'))}")
    else:
        print("\nSender IP Analysis: No IP to analyze.")

    print("\n--- Domain Analysis ---")
    if virustotal_domain_results:
        if "error" in virustotal_domain_results:
            print(f"{GREEN}VirusTotal Check:{END} {colorize_value(virustotal_domain_results['error'])}")
        else:
            print("VirusTotal Domain Last Analysis Stats:")
            for key, value in virustotal_domain_results.items():
                print(f"  {GREEN}{key.capitalize()}:{END} {colorize_value(value)}")
    else:
        print("VirusTotal Check: No domain to analyze.")

    if whois_info:
        if "error" in whois_info:
            print(f"{GREEN}WHOIS Info:{END} {colorize_value(whois_info['error'])}")
        else:
            print("WHOIS Information:")
            print(f"  {GREEN}Creation Date:{END} {colorize_value(whois_info.get('creation_date', 'N/A'))}")
            print(f"  {GREEN}Expiration Date:{END} {colorize_value(whois_info.get('expiration_date', 'N/A'))}")
            print(f"  {GREEN}Organization:{END} {colorize_value(whois_info.get('organization', 'N/A'))}")
    else:
        print("WHOIS Info: No domain to analyze.")
    print("----------------------")


def check_suspicious_subject(msg, suspicious_words):
    try:
        subject = msg['Subject']
        if not subject:
            print("No subject found.")
            return

        for word in suspicious_words:
            if word.lower() in subject.lower():
                print(f"{GREEN}Suspicious subject detected:{END} '{subject}' contains the word '{word}'.")
                return

        print("No suspicious words found in the subject.")
    except Exception as e:
        print(f"An error occurred while checking the subject: {e}")


def extract_urls_from_email(msg):
    urls = []
    try:
        
        if msg.is_multipart():
            parts = msg.walk()
            body = ""
            for part in parts:
                if part.get_content_type() == 'text/plain':
                    body += part.get_content()
        else:
            body = msg.get_content()
       
        url_regex = re.compile(
            r'((?:http|ftp)s?://[^\s/$.?#].[^\s]*)', re.IGNORECASE)
        urls = url_regex.findall(body)
        return urls
    except Exception as e:
        print(f"An error occurred while extracting URLs: {e}")
        return []


def extract_attachments_from_email(msg, output_dir='attachments'):
    attachments = []
    try:
        os.makedirs(output_dir, exist_ok=True)
        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            filename = part.get_filename()
            if filename:
                filepath = os.path.join(output_dir, filename)
                with open(filepath, 'wb') as fp:
                    fp.write(part.get_payload(decode=True))
                attachments.append(filepath)
        return attachments
    except Exception as e:
        print(f"An error occurred while extracting attachments: {e}")
        return []

def main():
    runPEnv()
    print_green("Welcome to the Email Analysis Tool!")
    file_path = input("Please enter the path to the email file (eml format): ").strip()

    if not os.path.isfile(file_path):
        print("Error: File not found. Please ensure the path is correct.")
        return

    try:
        
        msg = read_email_file(file_path)
        if not msg:
            print("Failed to read the email file.")
            return

       
        print_green("\nExtracting basic email details...")
        email_details = extract_basic_email_details(msg)
        print_email_details(email_details)

        
        print_green("\nAnalyzing sender domain and IP...")
        analyze_sender_domain_and_ip(email_details)

        
        print_green("\nChecking for suspicious subject keywords...")
        suspicious_words = ["urgent", "invoice", "payment", "sensitive", "action required"] 
        check_suspicious_subject(msg, suspicious_words)

        
        print_green("\nExtracting URLs from the email...")
        urls = extract_urls_from_email(msg)
        if urls:
            print(f"Found {len(urls)} URL(s):")
            for url in urls:
                print(f"- {url}")
        else:
            print("No URLs found in the email.")

        print_green("\nExtracting attachments from the email...")
        attachments = extract_attachments_from_email(msg)
        if attachments:
            print(f"Extracted {len(attachments)} attachment(s):")
            for attachment in attachments:
                print(f"- {attachment}")
        else:
            print("No attachments found in the email.")

        # Step 6: Analyze the URLs
        if urls:
            print_green("\nAnalyzing URLs on VirusTotal...")
            for url in urls:
                print(f"\nChecking URL: {url}")
                vt_url_results = check_virustotal_url(url)
                if "error" in vt_url_results:
                    print(f"{GREEN}VirusTotal URL Check Error:{END} {colorize_value(vt_url_results['error'])}")
                else:
                    print("VirusTotal URL Analysis Stats:")
                    for key, value in vt_url_results.items():
                        print(f"  {GREEN}{key.capitalize()}:{END} {colorize_value(value)}")
        else:
            print("No URLs to analyze.")
    except Exception as e:
        print(f"An error occurred while processing the email: {e}")

if __name__ == "__main__":
    main()
