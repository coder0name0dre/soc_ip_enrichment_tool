import os
import requests
import time
import csv
from datetime import datetime, timezone

# Load API Keys from environment #

# We read API keys from environment variables instead of hardcoding them.
# Your AbuseIPDB and VirusTotal API keys that would have been set into your ~/.zshrc file.

ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# If keys are missing, stop early with a helpful message
if not ABUSE_API_KEY or not VT_API_KEY:
    print("Error: Missing API keys.")
    print("Make sure ABUSEIPDB_API_KEY and VIRUSTOTAL_API_KEY are set.")
    exit(1)


# Input Data (IPs to Analyse) #

ips = [
    "8.8.8.8",
    "185.220.101.1",
    "45.155.205.233"
]


# Output File #

# CSV file where results will be stored.
# If it already exists, we append to it.

csv_file = "soc_ip_enrichment_results.csv"


# AbuseIPDB Lookup Function #

def check_abuseipdb(ip):
# Query AbuseIPDB for an IP address.
# Returns a confidence score (int) or None on error

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Accept": "application/json",
        "Key": ABUSE_API_KEY
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    response = requests.get(url, headers=headers, params=params)

    if response.status_code != 200:
        return None
    
    data = response.json()["data"]
    return data["abuseConfidenceScore"]


# VirusTotal Lookup Function #

def check_virustotal(ip):
# Query Virus Total for IP reputation.
# Return a malicious and suspicious count (int) or None on error

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "x-apikey": VT_API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return None
    
    stats = response.json()["data"]["attributes"]["last_analysis_stats"]
    return stats["malicious"], stats["suspicious"]


# Risk Scoring Logic #

def calculate_risk(abuse_score, vt_malicious, vt_suspicious):
# Combine different intel sources into a single risk score.

    risk = 0

    if abuse_score >= 50:
        risk += 50

    if vt_malicious >= 5:
        risk += 50

    if vt_suspicious >= 3:
        risk += 20

    return min(risk, 100)


def verdict(score):
# Convert a numeric score into an analyst friendly verdict.

    if score >= 61:
        return "Likely Malicious!"
    elif score >= 21:
        return "Suspicious!"
    else:
        return "Likely Benign!"
    

# CSV Setup #

# Check if the CSV file already exists
file_exists = os.path.isfile(csv_file)

# Open the CSV file in append mode
with open(csv_file, mode="a", newline="") as file:
    writer = csv.writer(file)

    # If this is a new file, write the header row
    if not file_exists:
        writer.writerow([
            "timestamp_utc",
            "ip_address",
            "abuseipdb_score",
            "vt_malicious",
            "vt_suspicious",
            "risk_score",
            "verdict"
        ])


    # Main Analysis Loop #

    for ip in ips:
        print("\n----------------------------------")
        print(f"Analysing IP: {ip}")

        abuse_score = check_abuseipdb(ip)
        vt_results = check_virustotal(ip)

        if abuse_score is None or vt_results is None:
            print("Error retrieving data for IP")
            continue

        vt_malicious, vt_suspicious = vt_results
        risk_score = calculate_risk(abuse_score, vt_malicious, vt_suspicious)
        decision = verdict(risk_score)

        # Generate a UTC timestamp in DD/MM/YYYY format
        timestamp = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M:%S UTC")
        
        # Print analyst friendly output
        print(f"AbuseIPDB Score: {abuse_score}")
        print(f"VirusTotal Malicious: {vt_malicious}")
        print(f"VirusTotal Suspicious: {vt_suspicious}")
        print(f"Combined Risk Score: {risk_score}")
        print(f"Verdict: {decision}")

        # Write results to CSV
        writer.writerow([
            timestamp,
            ip,
            abuse_score,
            vt_malicious,
            vt_suspicious,
            risk_score,
            decision
        ])

        # VirusTotal free tier rate limit
        time.sleep(15)