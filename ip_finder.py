import socket
import requests
import dns.resolver
import whois
import ssl
import sys
import datetime

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP-Proxy"
}

def banner():
    print("""
---
|_ |  _ \\      |  (| |   __ / | ___ _ __
| || |) |_____| |  | | ' \\ / ` | | / _ \\ '|
| ||  /|  | | | | | | (| |  |  / |
|||        ||   ||| ||_,||  __|_|

IP-FINDER v2.0.1
──────────────────────────────────────────

[*] Advanced network lookup & reconnaissance utility
[+] Status: Ready
""")

def get_my_ip():
    try:
        ip = requests.get('https://api.ipify.org', timeout=5).text
        print(f"My public IP: {ip}")
    except Exception as e:
        print(f"Failed to get public IP: {e}")

def ip_lookup(ip):
    try:
        domain = socket.gethostbyaddr(ip)[0]
        print(f"Reverse DNS for {ip}: {domain}")
    except Exception as e:
        print(f"Reverse DNS lookup failed: {e}")

def domain_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"IP for {domain}: {ip}")
        return ip
    except Exception as e:
        print(f"Domain lookup failed: {e}")
        return None

def dns_records(domain):
    types = ["A","AAAA","MX","NS","TXT","CNAME","SOA","PTR"]
    for t in types:
        try:
            answers = dns.resolver.resolve(domain, t, raise_on_no_answer=False)
            if answers.rrset:
                print(f"{t} Records:")
                for rdata in answers:
                    print(f"  - {rdata.to_text()}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            continue
        except Exception as e:
            print(f"DNS {t} lookup error: {e}")

def ip_information(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        if r.get('status') == 'success':
            fields = ['country','regionName','city','isp','org','as','timezone','zip','query']
            print(f"Information for IP: {ip}")
            for f in fields:
                print(f"{f.capitalize():<12}: {r.get(f, 'N/A')}")
        else:
            print(f"No info found for IP {ip}")
    except Exception as e:
        print(f"IP info fetch failed: {e}")

def whois_lookup(target):
    try:
        w = whois.whois(target)
        print(f"WHOIS information for {target}:")
        for k,v in w.items():
            if v:
                if isinstance(v, list):
                    v = ', '.join(str(i) for i in v)
                print(f"{k}: {v}")
    except Exception as e:
        print(f"WHOIS lookup failed: {e}")

def port_scan(ip):
    open_ports = []
    print(f"Scanning common ports on {ip}...")
    for port, service in COMMON_PORTS.items():
        try:
            s = socket.socket()
            s.settimeout(1)
            if s.connect_ex((ip, port)) == 0:
                print(f"Port {port} ({service}): OPEN")
                open_ports.append(port)
            s.close()
        except Exception:
            pass
    if not open_ports:
        print("No common ports open found")
    return open_ports

def grab_http_headers(target):
    try:
        r = requests.get(f"http://{target}", timeout=5)
        print(f"HTTP headers from http://{target}:")
        for k,v in r.headers.items():
            print(f"{k}: {v}")
    except Exception as e:
        print(f"HTTP header grab failed: {e}")

def grab_https_cert(target):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((target, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                print(f"SSL Certificate for {target}:")
                for key, value in cert.items():
                    if isinstance(value, (list, tuple)):
                        print(f"{key}:")
                        for item in value:
                            print(f"  {item}")
                    else:
                        print(f"{key}: {value}")
    except Exception as e:
        print(f"SSL certificate fetch failed: {e}")

def subdomain_enum(domain):
    subs = [
        'www','mail','ftp','webmail','smtp','ns1','ns2','blog','vpn','m',
        'dev','test','admin','portal','web','server','ns','shop','api',
        'staging','beta','demo'
    ]
    found = False
    print(f"Enumerating common subdomains for {domain}:")
    for sub in subs:
        d = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(d)
            print(f"{d}: {ip}")
            found = True
        except Exception:
            continue
    if not found:
        print("No common subdomains found")

def save_results(data, filename="scan_results.txt"):
    try:
        with open(filename, "w", encoding='utf-8') as f:
            f.write(data)
        print(f"Results saved to {filename}")
    except Exception as e:
        print(f"Failed to save results: {e}")

def main():
    banner()
    while True:
        print("""
1. My IP
2. IP Lookup (Reverse DNS)
3. Domain Lookup
4. DNS Records
5. IP Information (GeoIP etc)
6. WHOIS Lookup
7. Port Scan (Common ports)
8. Grab HTTP Headers
9. Grab HTTPS Certificate Info
10. Subdomain Enumeration
11. Exit
──────────────────────────────────────────""")
        c = input("Select option > ").strip()
        if c == '1':
            get_my_ip()
        elif c == '2':
            ip = input("Enter IP address: ").strip()
            ip_lookup(ip)
        elif c == '3':
            d = input("Enter domain: ").strip()
            domain_lookup(d)
        elif c == '4':
            d = input("Enter domain: ").strip()
            dns_records(d)
        elif c == '5':
            ip = input("Enter IP address: ").strip()
            ip_information(ip)
        elif c == '6':
            t = input("Enter domain or IP: ").strip()
            whois_lookup(t)
        elif c == '7':
            ip = input("Enter IP address: ").strip()
            port_scan(ip)
        elif c == '8':
            t = input("Enter domain or IP: ").strip()
            grab_http_headers(t)
        elif c == '9':
            t = input("Enter domain or IP: ").strip()
            grab_https_cert(t)
        elif c == '10':
            d = input("Enter domain: ").strip()
            subdomain_enum(d)
        elif c == '11':
            sys.exit()
        else:
            print("Invalid option")

if __name__ == "__main__":
    main()
