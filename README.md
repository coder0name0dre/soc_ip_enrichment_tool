# SOC IP Enrichment Tool

This project is a Python script designed to simulate how a Security Operations Centre (SOC) enriches IP addresses using threat intelligence.

The script:

- takes a list of IP addresses
- queries **AbuseIPDB** and **VirusTotal**
- combines the results into a simple risk score
- outputs results to the terminal
- saves results to a CSV file with UTC timestamps

**This script does not block traffic or take automated action.**

---

## Requirements

- macOS (tested)
- Linux or Windows should also work with minor changes
- Python 3.9+

### Required Python Library

This script uses the `requests` library.

Install it with:

```
pip3 install requests
```

---

## API Keys Required

You will need free API keys from:

- [www.abuseipdb.com](https://www.abuseipdb.com/)
- [www.virustotal.com](https://www.virustotal.com/)

**Do Not hardcode API keys into the script**

---

## Setting API Keys (macOS)

### Create an AbuseIPDB API Key

1. Open your browser and go to:

```
https://www.abuseipdb.com/
```

2. Click **Sign Up** at the top right of thew homepage and create a free account.
3. After logging in, go to **My API**.
4. Under **Create API Key**, click on **Create Key**.
5. Copy your API Key.
  - It will look like a long random string.
  - Do not paste it into the python script.

Keep this key safe.

### Create a VirusTotal API Key

