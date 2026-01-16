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

1. Open your browser and go to:

```
https://www.virustotal.com/
```

2. Create a free account or log in.
3. Click on your profile icon (top right corner).
4. Select API Key.
5. Copy your API Key.

### Store API Keys Securely (macOS)

We will store the keys as environment variables.
This keeps them out of the code and safe.

1. Open your terminal

Press:
- Cmd + Space
- Type Terminal
- Press Enter

2. Edit your shell configuration file

On macOS (default shell is `zsh`), run:

```
nano ~/.zshrc
```

This opens a text editor in the terminal.

3. Add your API keys

At the bottom of the file, add:

```
export ABUSEIPDB_API_KEY="PASTE_YOUR_ABUSEIPDB_KEY_HERE"
export VIRUSTOTAL_API_KEY="PASTE_YOUR_VIRUSTOTAL_KEY_HERE"
```

- **Replace the placeholder text with your actual keys**
- **Keep the quotation marks**

4. Save and exit

- Press Ctrl + O, and then Enter (save)
- Press Ctrl + X (exit)

### Load the API Keys into your Terminal session

Run:

```
source ~/.zshrc
```

This makes the new variables available immediately.

### Verify you API Keys are set

Run:

```
echo $ABUSEIPDB_API_KEY
echo $VIRUSTOTAL_API_KEY
```

If you see your keys printed, the setup worked

If nothing prints, the variables are not set correctly

---

## How To Run The Script

1. Clone or download the repository
2. Navigate into the project directory:

```
cd soc_ip_enrichment_tool
```

3. Run the script

```
python3 soc_ip_enrichment.py
```

---
