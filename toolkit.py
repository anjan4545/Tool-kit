import argparse
import socket
import concurrent.futures
import paramiko
import ftplib
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import os
import re

# Main Toolkit Controller
def main():
    banner = """
          Penetration Testing Toolkit
    """
    print(banner)

    parser = argparse.ArgumentParser(description=' Pentesting Toolkit')
    subparsers = parser.add_subparsers(dest='command', help='Module to execute')

    # Port Scanner Module
    port_parser = subparsers.add_parser('scan', help='Port scanning module')
    port_parser.add_argument('target', help='Target IP address or hostname')
    port_parser.add_argument('-p', '--ports', default='1-1024', 
                             help='Port range to scan (e.g., 80,443 or 1-1000)')
    port_parser.add_argument('-t', '--threads', type=int, default=50,
                             help='Number of threads')

    # Brute Forcer Module
    brute_parser = subparsers.add_parser('brute', help='Brute forcing module')
    brute_parser.add_argument('service', help='Target service (ssh, ftp, http)')
    brute_parser.add_argument('-u', '--username', help='Username or file containing usernames')
    brute_parser.add_argument('-w', '--wordlist', required=True,
                              help='Password wordlist file')
    brute_parser.add_argument('-p', '--port', type=int, 
                              help='Target port (if not default)')

    # Vulnerability Scanner Module
    vuln_parser = subparsers.add_parser('vulnscan', help='Vulnerability scanning module')
    vuln_parser.add_argument('url', help='Target URL')
    vuln_parser.add_argument('-d', '--depth', type=int, default=1,
                             help='Crawling depth')

    # Directory Buster Module
    dir_parser = subparsers.add_parser('dirbust', help='Directory busting module')
    dir_parser.add_argument('url', help='Target URL')
    dir_parser.add_argument('-w', '--wordlist', required=True,
                            help='Wordlist file')

    args = parser.parse_args()

    if args.command == 'scan':
        scan_ports(args.target, args.ports, args.threads)
    elif args.command == 'brute':
        brute_force(args.service, args.username, args.wordlist, args.port)
    elif args.command == 'vulnscan':
        scan(args.url, args.depth)
    elif args.command == 'dirbust':
        bust(args.url, args.wordlist)
    else:
        parser.print_help()

# Port Scanner Function
def scan_ports(target, port_range="1-1024", max_threads=50):
    """Scan target for open ports"""
    print(f"\n[+] Starting port scan on {target}")
    
    # Parse port range
    try:
        if '-' in port_range:
            start, end = map(int, port_range.split('-'))
            ports = range(start, end + 1)
        else:
            ports = [int(p) for p in port_range.split(',')]
    except ValueError:
        print("[-] Invalid port range format. Use '1-1000' or '80,443'")
        return

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("[-] Could not resolve hostname")
        return

    print(f"[*] Scanning {target_ip} ({target})")
    print(f"[*] Port range: {port_range}")
    print(f"[*] Threads: {max_threads}")

    open_ports = []

    def check_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((target_ip, port))
                if result == 0:
                    service = socket.getservbyport(port) if port <= 65535 else "unknown"
                    print(f"[+] Port {port} ({service}) is open")
                    open_ports.append((port, service))
        except (socket.error, socket.timeout, OverflowError):
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        executor.map(check_port, ports)

    print(f"\n[+] Scan completed. Found {len(open_ports)} open ports.")
    return open_ports

# Brute Forcer Function
def brute_force(service, username, wordlist_file, port=None):
    """Perform brute force attack against specified service"""
    
    print(f"\n[+] Starting brute force attack on {service.upper()} service")
    
    # Get credentials from files if paths are provided
    usernames = []
    if username and os.path.exists(username):
        with open(username, 'r') as f:
            usernames = [line.strip() for line in f.readlines()]
    elif username:
        usernames = [username]
    else:
        print("[-] No username or username file provided")
        return False
    
    if not os.path.exists(wordlist_file):
        print("[-] Wordlist file not found")
        return False
    
    passwords = []
    with open(wordlist_file, 'r') as f:
        passwords = [line.strip() for line in f.readlines()]
    
    print(f"[*] Target: {service}")
    print(f"[*] Usernames loaded: {len(usernames)}")
    print(f"[*] Passwords loaded: {len(passwords)}")
    
    service_port = {
        'ssh': 22,
        'ftp': 21,
        'http': 80
    }.get(service.lower(), port)
    
    if service_port is None:
        print("[-] Port must be specified for custom services")
        return False
    
    # Service-specific brute force functions
    handlers = {
        'ssh': brute_ssh,
        'ftp': brute_ftp,
        'http': brute_http_auth
    }.get(service.lower())
    
    if not handlers:
        print("[-] Unsupported service")
        return False
    
    credentials = None
    
    # Try credentials combinations
    for user in usernames:
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(
                lambda p: handlers(target, user, p, service_port),
                passwords
            ))
            
            for result in results:
                if result:
                    credentials = (user, result)
                    break
        
        if credentials:
            break
    
    if credentials:
        print(f"\n[+] Found valid credentials!")
        print(f"[+] Username: {credentials[0]}")
        print(f"[+] Password: {credentials[1]}")
        return credentials
    else:
        print("\n[-] No valid credentials found")
        return None

def brute_ssh(target, username, password, port):
    """Brute force SSH service"""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(target, port=port, username=username, password=password, timeout=5)
        ssh.close()
        return password
    except:
        return None

def brute_ftp(target, username, password, port):
    """Brute force FTP service"""
    try:
        ftp = ftplib.FTP()
        ftp.connect(target, port, timeout=5)
        ftp.login(username, password)
        ftp.quit()
        return password
    except:
        return None

def brute_http_auth(target, username, password, port):
    """Brute force HTTP basic authentication"""
    url = f"http://{target}:{port}"
    try:
        resp = requests.get(url, auth=(username, password), timeout=5)
        if resp.status_code != 401:
            return password
    except:
        pass
    return None

# Vulnerability Scanner Class
class VulnerabilityScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User -Agent': 'VulnScanner/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        })
        self.vulnerabilities = []

    def scan(self, target_url, depth=1):
        """Scan target URL for common vulnerabilities"""
        self._crawl_and_scan(target_url, depth)
        return self.report_findings()

    def _crawl_and_scan(self, url, depth, current_depth=0, visited=None):
        """Recursive crawler and scanner"""
        if visited is None:
            visited = set()
        
        if url in visited or current_depth > depth:
            return
        
        print(f"[*] Scanning: {url}")
        visited.add(url)
        
        try:
            response = self.session.get(url, timeout=10)
            if response.status_code != 200:
                return
            
            self._check_xss(response)
            self._check_sqli(response)
            # Add additional vulnerability checks here
            
            # Parse links and continue crawling
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith('javascript:') or href.startswith('mailto:'):
                    continue
                absolute_url = urljoin(url, href)
                if absolute_url.startswith(url):  # Stay within target scope
                    self._crawl_and_scan(
                        absolute_url,
                        depth,
                        current_depth + 1,
                        visited
                    )
        
        except requests.RequestException as e:
            print(f"[-] Error scanning {url}: {str(e)}")

    def _check_xss(self, response):
        """Check for potential XSS vulnerabilities"""
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        # Simple reflection test
        parsed_url = urlparse(response.url)
        query = parse_qs(parsed_url.query)
        for param in query:
            test_payload = "<script>alert('XSS')</script>"
            test_url = self._inject_payload(response.url, param, test_payload)
            test_response = self.session.get(test_url)
            if test_payload in test_response.text:
                self._log_vulnerability(
                    'XSS', 
                    f"Reflected XSS via parameter: {param}",
                    test_url
                )

    def _inject_payload(self, url, param, payload):
        """Inject payload into URL parameter"""
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        query[param] = [payload]
        new_query = urlencode(query, doseq=True)
        return urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path,
             parsed.params, new_query, parsed.fragment)
        )

    def _log_vulnerability(self, vuln_type, description, url):
        """Log found vulnerabilities"""
        self.vulnerabilities.append({
            'type': vuln_type,
            'description': description,
            'url': url
        })

    def report_findings(self):
        """Generate vulnerability report"""
        if self.vulnerabilities:
            print("\n[+] Vulnerability Report:")
            for vuln in self.vulnerabilities:
                print(f"\n- {vuln['type']}: {vuln['description']}")
                print(f"  URL: {vuln['url']}")
            return True
        else:
            print("\n[-] No vulnerabilities found")
            return False

def scan(target_url, depth=1):
    scanner = VulnerabilityScanner()
    return scanner.scan(target_url, depth)

# Directory Buster Function
def bust(target_url, wordlist_file, extensions=None, threads=20):
    """Perform directory busting against web application"""
    
    print(f"\n[+] Starting directory busting on {target_url}")
    
    if extensions is None:
        extensions = ['', '.php', '.html', '.asp', '.aspx']
    
    try:
        with open(wordlist_file, 'r') as f:
            wordlist = [line.strip() for line in f.readlines()]
    except IOError:
        print("[-] Could not read wordlist file")
        return False
    
    print(f"[*] Words loaded: {len(wordlist)}")
    print(f"[*] Extensions: {', '.join(ext for ext in extensions if ext)}")
    print(f"[*] Threads: {threads}")
    
    found = []
    
    def check_path(path):
        url = f"{target_url.rstrip('/')}/{path}"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code < 400:
                print(f"[+] Found: {url} ({response.status_code})")
                found.append((url, response.status_code))
        except requests.RequestException:
            pass
    
    # Generate all possible paths to check
    paths = []
    for word in wordlist:
        for ext in extensions:
            paths.append(f"{word}{ext}")
    
    # Check paths with threading
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(check_path, paths)
    
    print(f"\n[+] Directory busting complete. Found {len(found)} valid paths.")
    return found

if __name__ == '__main__':
    main()
