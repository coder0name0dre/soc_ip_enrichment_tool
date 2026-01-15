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

