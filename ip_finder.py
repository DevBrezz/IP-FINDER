#!/usr/bin/env python3
"""IP-FINDER v1.0.0 - network recon utility. Author: DevBrezz."""

import datetime
import errno
import importlib.util
import ipaddress
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from urllib.parse import urlparse

TOOL_NAME = "IP-FINDER"
VERSION = "1.0.0"
AUTHOR = "DevBrezz"

API_TIMEOUT = 6
PORT_TIMEOUT = 1
DNS_TIMEOUT = 3

REQUIRED_DEPS = {"requests": "requests", "dns": "dnspython"}
OPTIONAL_DEPS = {"whois": "python-whois", "colorama": "colorama"}

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP-Proxy",
}

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "smtp", "ns1", "ns2", "blog", "vpn",
    "m", "dev", "test", "admin", "portal", "web", "server", "ns", "shop",
    "api", "staging", "beta", "demo",
]

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
PROPAGATION_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]

PUBLIC_RESOLVERS = [
    ("Google", "8.8.8.8"),
    ("Cloudflare", "1.1.1.1"),
    ("Quad9", "9.9.9.9"),
    ("OpenDNS", "208.67.222.222"),
]

_DOMAIN_LABEL = re.compile(r"^(?!-)[A-Za-z0-9\u00a1-\uffff-]{1,63}(?<!-)$")
_TLD_LABEL = re.compile(r"^[A-Za-z\u00a1-\uffff]{2,63}$")

_requests = None
_dns = None
_whois = None

_color_enabled = False
try:
    import colorama
    colorama.init()
    _color_enabled = True
except ImportError:
    pass

GREEN = "\033[92m" if _color_enabled else ""
YELLOW = "\033[93m" if _color_enabled else ""
RED = "\033[91m" if _color_enabled else ""
DRED = "\033[38;5;124m" if _color_enabled else ""
CYAN = "\033[96m" if _color_enabled else ""
WHITE = "\033[97m" if _color_enabled else ""
BOLD = "\033[1m" if _color_enabled else ""
RESET = "\033[0m" if _color_enabled else ""


class ResultCollector:
    def __init__(self):
        self.sections = []

    def add(self, title, lines):
        if isinstance(lines, str):
            lines = lines.splitlines()
        self.sections.append((title, list(lines or [])))

    def empty(self):
        return not self.sections

    def render(self, target):
        out = [
            f"{TOOL_NAME} v{VERSION} Results",
            f"Timestamp: {datetime.datetime.now().isoformat()}",
            f"Target: {target}",
            "",
        ]
        for title, lines in self.sections:
            out.append(f"== {title} ==")
            if lines:
                out.extend(f"  {ln}" for ln in lines)
            else:
                out.append("  (no results)")
            out.append("")
        return "\n".join(out)


RESULTS = ResultCollector()


def term_width(default=80):
    try:
        return max(40, min(120, shutil.get_terminal_size((default, 24)).columns))
    except Exception:
        return default


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def print_banner():
    art = [
        " ___ ____        _______ _           __",
        "|_ _|  _ \\      |  ___(_)_ __   __| | ___ _ __",
        " | || |_) |_____| |_  | | '_ \\ / _` |/ _ \\ '__|",
        " | ||  __/     |  _| | | | | | (_| |  __/ |",
        "|___|_|        |_|   |_|_| |_|\\__,_|\\___|_|",
    ]
    print(f"{GREEN}{BOLD}")
    for line in art:
        print(line)
    print(f"{RESET}{CYAN}  {TOOL_NAME} v{VERSION}  [BY: {AUTHOR}]{RESET}")
    print(f"{DRED}  {'=' * min(term_width() - 2, 66)}{RESET}")
    print()


def status(label, color, message):
    print(f"{color}[{label}]{RESET} {message}")


def info(msg):
    status("INFO", CYAN, msg)


def success(msg):
    status("SUCCESS", GREEN, msg)


def warning(msg):
    status("WARNING", YELLOW, msg)


def error(msg):
    status("ERROR", RED, msg)


def section(title):
    print()
    print(f"{BOLD}{CYAN}[::] {title.upper()}{RESET}")
    print(f"{DRED}{'-' * min(term_width() - 2, 66)}{RESET}")


def ask(label):
    try:
        return input(f"{GREEN}[~]{RESET} {label}: ").strip()
    except EOFError:
        return ""


def pause():
    try:
        input(f"\n{CYAN}[~]{RESET} Press Enter to return to menu...")
    except EOFError:
        pass


def check_dependencies():
    missing_required = [pkg for mod, pkg in REQUIRED_DEPS.items()
                        if importlib.util.find_spec(mod) is None]
    missing_optional = [pkg for mod, pkg in OPTIONAL_DEPS.items()
                        if importlib.util.find_spec(mod) is None]
    return (not missing_required), missing_required, missing_optional


def load_optional_imports():
    global _requests, _dns, _whois
    try:
        import requests as _r
        _requests = _r
    except ImportError:
        pass
    try:
        import dns as _d
        import dns.resolver  # noqa: F401
        _dns = _d
    except ImportError:
        pass
    try:
        import whois as _w
        _whois = _w
    except ImportError:
        pass


def _require(name):
    mod = {"requests": _requests, "dns": _dns, "whois": _whois}.get(name)
    if mod is None:
        package = REQUIRED_DEPS.get(name) or OPTIONAL_DEPS.get(name, name)
        error(f"Missing dependency: {package}")
        print(f"  pip install {package}")
    return mod


def validate_ip(value):
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except (ValueError, TypeError):
        return False


def parse_ip(value):
    try:
        return ipaddress.ip_address(value)
    except (ValueError, TypeError):
        return None


def validate_domain(domain):
    if not isinstance(domain, str):
        return False
    domain = domain.strip().rstrip(".")
    if not domain or len(domain) > 253 or ".." in domain:
        return False
    try:
        domain = domain.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return False
    labels = domain.split(".")
    if len(labels) < 2 or not all(_DOMAIN_LABEL.fullmatch(label) for label in labels):
        return False
    tld = labels[-1]
    return bool(_TLD_LABEL.fullmatch(tld) or re.fullmatch(r"xn--[a-z0-9-]{2,59}", tld, re.I))


def normalize_url(raw):
    raw = (raw or "").strip()
    if not raw or any(ch.isspace() for ch in raw):
        return None
    try:
        parsed = urlparse(raw)
    except ValueError:
        # urlparse can reject malformed IPv6 brackets before validation.
        return None
    if parsed.scheme and parsed.scheme.lower() not in ("http", "https"):
        return None
    if parsed.scheme:
        if not parsed.hostname or parsed.username or parsed.password:
            return None
        try:
            # Accessing .port also validates malformed port syntax.
            port = parsed.port
        except ValueError:
            return None
        host = parsed.hostname
        if not (validate_ip(host) or validate_domain(host)):
            return None
        if port is not None and not (1 <= port <= 65535):
            return None
        return raw
    if ":" in raw and not raw.startswith("["):
        try:
            ipaddress.IPv6Address(raw)
            return f"http://[{raw}]"
        except ValueError:
            pass
    candidate = "http://" + raw
    try:
        parsed = urlparse(candidate)
        hostname = parsed.hostname
    except ValueError:
        return None
    if not hostname or parsed.username or parsed.password:
        return None
    if not (validate_ip(hostname) or validate_domain(hostname)):
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    if port is not None and not (1 <= port <= 65535):
        return None
    return candidate


def classify_target(value):
    value = (value or "").strip()
    if not value:
        return ("invalid", None)
    if value.startswith(("http://", "https://")):
        try:
            parsed = urlparse(value)
            host = parsed.hostname
            port = parsed.port  # Validate malformed ports consistently.
        except ValueError:
            return ("invalid", None)
        if not host or parsed.username or parsed.password or (port is not None and not 1 <= port <= 65535):
            return ("invalid", None)
        value = host
    if validate_ip(value):
        return ("ip", value)
    if validate_domain(value):
        try:
            value = value.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError:
            return ("invalid", value)
        return ("domain", value)
    return ("invalid", value)


def http_get_json(url, accept=None, timeout=API_TIMEOUT):
    requests = _require("requests")
    if not requests:
        return None, "requests not available"
    headers = {"Accept": accept} if accept else {}
    try:
        r = requests.get(url, timeout=timeout, headers=headers)
        r.raise_for_status()
        return r.json(), None
    except requests.exceptions.RequestException as exc:
        return None, f"{type(exc).__name__}: {exc}"
    except ValueError:
        return None, "response was not JSON"


def get_my_ip():
    requests = _require("requests")
    if not requests:
        return None
    try:
        info("Contacting public IP service...")
        r = requests.get("https://api.ipify.org", timeout=API_TIMEOUT)
        r.raise_for_status()
        ip = r.text.strip()
        if not validate_ip(ip):
            error("Public IP API returned an invalid address.")
            return None
        success(f"Public IP: {GREEN}{ip}{RESET}")
        return ip
    except Exception as exc:
        error(f"Failed to obtain public IP: {exc}")
        return None


def reverse_dns_lookup(ip):
    parsed = parse_ip(ip)
    if not parsed:
        error(f"Invalid IP address: {ip}")
        return None
    try:
        info("Reverse DNS query...")
        domain = socket.gethostbyaddr(str(parsed))[0]
        success(f"{parsed} -> {GREEN}{domain}{RESET}")
        return domain
    except socket.herror:
        warning("No reverse DNS entry found.")
    except socket.gaierror as exc:
        error(f"Resolution error: {exc}")
    except Exception as exc:
        error(f"Lookup failed: {exc}")
    return None


def domain_to_ip(domain):
    if not validate_domain(domain):
        error(f"Invalid domain: {domain}")
        return None
    try:
        info("Resolving domain...")
        infos = socket.getaddrinfo(domain, None)
        ips = sorted({item[4][0] for item in infos})
        for ip in ips:
            success(f"{domain} -> {GREEN}{ip}{RESET}")
        return ips
    except socket.gaierror:
        error("Domain resolution failed.")
    except Exception as exc:
        error(f"Lookup error: {exc}")
    return None


def lookup_dns_records(domain):
    dns = _require("dns")
    if not dns:
        return None
    import dns.resolver

    if not validate_domain(domain):
        error(f"Invalid domain: {domain}")
        return None

    collected = {}
    info(f"Querying DNS for {domain}...")
    for rtype in DNS_RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=DNS_TIMEOUT)
            records = [rdata.to_text() for rdata in answers]
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            error("Domain does not exist.")
            break
        except dns.resolver.NoNameservers:
            warning(f"{rtype}: no nameservers answered.")
            continue
        except dns.resolver.LifetimeTimeout:
            warning(f"{rtype}: query timed out.")
            continue
        except Exception as exc:
            warning(f"{rtype} failed: {type(exc).__name__}")
            continue
        if records:
            collected[rtype] = records

    if not collected:
        warning("No DNS records returned.")
        return None

    section(f"DNS records - {domain}")
    print(f"  {'Type':<8}{'Value'}")
    for rtype, records in collected.items():
        for i, record in enumerate(records):
            tag = rtype if i == 0 else ""
            print(f"  {tag:<8}{record}")
    return collected


def ip_geo_info(ip):
    requests = _require("requests")
    if not requests:
        return None
    parsed = parse_ip(ip)
    if not parsed:
        error(f"Invalid IP address: {ip}")
        return None

    info("Querying geolocation (ipwho.is, HTTPS)...")
    url = f"https://ipwho.is/{parsed}"
    data, err = http_get_json(url)
    if err:
        error(f"GeoIP failed: {err}")
        return None
    if not data or not data.get("success", False):
        error(f"GeoIP error: {data.get('message', 'unknown') if data else 'no data'}")
        return None

    connection = data.get("connection") or {}
    rows = [
        ("IP", data.get("ip", str(parsed))),
        ("Type", data.get("type", "N/A")),
        ("Country", data.get("country", "N/A")),
        ("Region", data.get("region", "N/A")),
        ("City", data.get("city", "N/A")),
        ("ISP", connection.get("isp", "N/A")),
        ("Org", connection.get("org", "N/A")),
        ("ASN", connection.get("asn", "N/A")),
        ("Timezone", (data.get("timezone") or {}).get("id", "N/A")),
        ("Source", "ipwho.is (HTTPS, community)"),
    ]
    section(f"Geolocation - {parsed}")
    lines = []
    for key, value in rows:
        print(f"  {key:<10}: {value}")
        lines.append(f"{key}: {value}")
    return lines


def _fmt_whois_value(value):
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    if isinstance(value, (datetime.date, datetime.datetime)):
        return value.isoformat()
    return str(value)


def whois_lookup(target):
    whois = _require("whois")
    if not whois:
        return None
    kind, value = classify_target(target)
    if kind == "invalid":
        error(f"Invalid domain or IP: {target}")
        return None
    try:
        info("Querying WHOIS...")
        data = whois.whois(value)
        if not data:
            error("No WHOIS data returned.")
            return None
        section(f"WHOIS - {value}")
        collected = {}
        for key, val in data.items():
            if val in (None, "", [], {}):
                continue
            formatted = _fmt_whois_value(val)
            collected[key] = formatted
            print(f"  {key}: {formatted}")
        if not collected:
            warning("No usable WHOIS fields.")
            return None
        return collected
    except Exception as exc:
        error(f"WHOIS lookup failed: {type(exc).__name__}")
        return None


def scan_port(parsed, port, results):
    family = socket.AF_INET6 if parsed.version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(PORT_TIMEOUT)
    try:
        rc = sock.connect_ex((str(parsed), port))
        if rc == 0:
            results[port] = "OPEN"
        elif rc in {errno.ECONNREFUSED, getattr(errno, "WSAECONNREFUSED", 10061)}:
            results[port] = "CLOSED"
        else:
            results[port] = "UNREACHABLE"
    except socket.timeout:
        results[port] = "TIMEOUT"
    except socket.gaierror:
        results[port] = "UNRESOLVED"
    except Exception:
        results[port] = "ERROR"
    finally:
        try:
            sock.close()
        except Exception:
            pass


def port_scan(ip):
    parsed = parse_ip(ip)
    if not parsed:
        error(f"Invalid IP address: {ip}")
        return None
    info(f"Scanning {len(COMMON_PORTS)} common TCP ports on {parsed}...")
    results = {}
    threads = []
    for port in COMMON_PORTS:
        t = threading.Thread(target=scan_port, args=(parsed, port, results), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout=3)

    section(f"Port scan - {parsed}")
    print(f"  {'Port':<7}{'Service':<14}{'State'}")
    rows = []
    for port in sorted(results):
        st = results[port]
        color = GREEN if st == "OPEN" else YELLOW if st in ("CLOSED", "TIMEOUT") else RED
        service = COMMON_PORTS.get(port, "Unknown")
        print(f"  {port:<7}{service:<14}{color}{st}{RESET}")
        rows.append(f"{port}/{service}: {st}")
    return rows


def grab_http_headers(target):
    requests = _require("requests")
    if not requests:
        return None
    url = normalize_url(target)
    if not url:
        error("Invalid URL or target. Use a valid domain, IP, or HTTP/HTTPS URL.")
        return None
    response = None
    try:
        info("Fetching HTTP headers...")
        # Stream the response so a large webpage is never downloaded just to read headers.
        response = requests.get(url, timeout=API_TIMEOUT, allow_redirects=True, stream=True,
                                headers={"User-Agent": f"{TOOL_NAME}/{VERSION}"})
        section(f"HTTP {response.status_code} - {url}")
        collected = {"status": str(response.status_code), "url": response.url}
        for key, value in response.headers.items():
            print(f"  {key}: {value}")
            collected[key] = value
        return collected
    except requests.exceptions.SSLError:
        error("TLS error contacting target.")
    except requests.exceptions.RequestException as exc:
        error(f"HTTP request failed: {type(exc).__name__}")
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass
    return None


def _cert_lines(cert):
    lines = []
    for key, val in cert.items():
        if isinstance(val, (list, tuple)):
            lines.append(f"{key}:")
            for item in val:
                if isinstance(item, tuple):
                    parts = ["=".join(map(str, sub)) if isinstance(sub, tuple) else str(sub)
                             for sub in item]
                    lines.append(f"  {', '.join(parts)}")
                else:
                    lines.append(f"  {item}")
        else:
            lines.append(f"{key}: {val}")
    return lines


def grab_https_cert(target):
    kind, value = classify_target(target)
    if kind == "invalid":
        error(f"Invalid domain or IP: {target}")
        return None
    server_hostname = value
    try:
        info(f"TLS handshake with {value}:443...")
        context = ssl.create_default_context()
        with socket.create_connection((value, 443), timeout=API_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    error("No certificate returned.")
                    return None
                section(f"TLS certificate - {value}")
                lines = _cert_lines(cert)
                for line in lines:
                    print(f"  {line}")
                return lines
    except ssl.SSLCertVerificationError as exc:
        error(f"Certificate verification failed: {exc.reason if hasattr(exc, 'reason') else exc}")
    except socket.timeout:
        error("TLS handshake timed out.")
    except socket.gaierror:
        error("DNS resolution failed for TLS target.")
    except ssl.SSLError as exc:
        error(f"TLS error: {exc}")
    except Exception as exc:
        error(f"Certificate retrieval failed: {type(exc).__name__}")
    return None


def subdomain_enum(domain):
    if not validate_domain(domain):
        error(f"Invalid domain: {domain}")
        return None
    info(f"Probing {len(COMMON_SUBDOMAINS)} common subdomains...")
    found = []
    for sub in COMMON_SUBDOMAINS:
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
        except (socket.gaierror, socket.herror):
            continue
        except Exception:
            continue
        success(f"{GREEN}{fqdn}{RESET} -> {ip}")
        found.append(f"{fqdn} -> {ip}")
    if not found:
        warning("No common subdomains found.")
        return []
    return found


def asn_lookup(target):
    kind, value = classify_target(target)
    if kind == "invalid":
        error(f"Invalid IP or domain: {target}")
        return None
    if kind == "domain":
        try:
            value = socket.gethostbyname(value)
        except socket.gaierror:
            error("Domain did not resolve to an IP.")
            return None
    parsed = parse_ip(value)
    if not parsed:
        error("Target is not a valid IP.")
        return None

    info("Querying ASN registry (ipwho.is, HTTPS)...")
    data, err = http_get_json(f"https://ipwho.is/{parsed}")
    if err:
        error(f"ASN lookup failed: {err}")
        return None
    if not data or not data.get("success", False):
        error(f"ASN error: {data.get('message', 'unknown') if data else 'no data'}")
        return None
    conn = data.get("connection") or {}
    asn_num = conn.get("asn", "N/A")
    asn_org = conn.get("org", "N/A")
    isp = conn.get("isp", "N/A")

    section(f"ASN / ISP - {parsed}")
    rows = [
        ("IP", data.get("ip", str(parsed))),
        ("ISP", isp),
        ("Organization", asn_org),
        ("ASN", (str(asn_num) if str(asn_num).upper().startswith("AS") else f"AS{asn_num}")
         if asn_num != "N/A" else "N/A"),
        ("AS org", asn_org),
        ("Source", "ipwho.is (HTTPS, community)"),
    ]
    lines = []
    for key, val in rows:
        print(f"  {key:<14}: {val}")
        lines.append(f"{key}: {val}")
    return lines


def rdap_lookup(target):
    kind, value = classify_target(target)
    if kind == "invalid":
        error(f"Invalid IP or domain: {target}")
        return None

    if kind == "ip":
        parsed = parse_ip(value)
        url = f"https://rdap.org/ip/{parsed}"
    else:
        url = f"https://rdap.org/domain/{value}"

    info(f"Querying RDAP at rdap.org for {value}...")
    data, err = http_get_json(url, accept="application/rdap+json")
    if err:
        error(f"RDAP request failed: {err}")
        return None
    if not isinstance(data, dict):
        error("RDAP response was not a JSON object.")
        return None

    section(f"RDAP - {value}")
    lines = []
    for field in ("name", "handle", "type", "country"):
        if data.get(field):
            print(f"  {field.capitalize():<13}: {data[field]}")
            lines.append(f"{field}: {data[field]}")

    for entity in data.get("entities", []) or []:
        roles = ", ".join(entity.get("roles", []))
        vcard = (entity.get("vcardArray") or [None, []])[1]
        for entry in vcard:
            if entry and entry[0] == "fn":
                print(f"  Entity       : {entry[3]} ({roles})")
                lines.append(f"Entity: {entry[3]} ({roles})")
                break

    for event in data.get("events", []) or []:
        action = event.get("eventAction", "")
        when = event.get("eventDate", "")
        if action in ("registration", "expiration", "last changed"):
            print(f"  {action.capitalize():<13}: {when}")
            lines.append(f"{action}: {when}")

    statuses = data.get("status") or []
    if statuses:
        print(f"  Status       : {', '.join(statuses)}")
        lines.append(f"Status: {', '.join(statuses)}")

    nameservers = data.get("nameservers") or []
    if nameservers:
        ns_list = [ns.get("ldhName", "?") for ns in nameservers]
        print(f"  Nameservers  : {', '.join(ns_list)}")
        lines.append(f"Nameservers: {', '.join(ns_list)}")

    if not lines:
        warning("RDAP returned no usable fields.")
        return None
    return lines


def _query_resolver(resolver_ip, domain, rtype, results):
    if not _dns:
        return
    import dns.resolver
    try:
        res = dns.resolver.Resolver(configure=False)
        res.nameservers = [resolver_ip]
        res.lifetime = DNS_TIMEOUT
        res.timeout = DNS_TIMEOUT
        answers = res.resolve(domain, rtype, lifetime=DNS_TIMEOUT)
        results[resolver_ip] = sorted(rdata.to_text() for rdata in answers)
    except dns.resolver.NoAnswer:
        results[resolver_ip] = []
    except dns.resolver.NXDOMAIN:
        results[resolver_ip] = "NXDOMAIN"
    except dns.resolver.LifetimeTimeout:
        results[resolver_ip] = "TIMEOUT"
    except Exception as exc:
        results[resolver_ip] = f"ERROR:{type(exc).__name__}"


def dns_propagation_check(domain, rtype):
    dns = _require("dns")
    if not dns:
        return None
    if not validate_domain(domain):
        error(f"Invalid domain: {domain}")
        return None
    rtype = (rtype or "").upper().strip()
    if rtype not in PROPAGATION_TYPES:
        error(f"Unsupported record type: {rtype}. Use: {', '.join(PROPAGATION_TYPES)}")
        return None

    results = {}
    threads = []
    info(f"Querying {len(PUBLIC_RESOLVERS)} resolvers for {domain} {rtype}...")
    for _name, ip in PUBLIC_RESOLVERS:
        t = threading.Thread(target=_query_resolver, args=(ip, domain, rtype, results), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout=DNS_TIMEOUT + 2)

    section(f"DNS propagation - {domain} {rtype}")
    print(f"  {'Resolver':<12}{'Address':<18}{'Answer'}")
    lines = []
    for label, ip in PUBLIC_RESOLVERS:
        ans = results.get(ip, "NO RESPONSE")
        if isinstance(ans, list):
            text = ", ".join(ans) if ans else "(empty)"
        else:
            text = str(ans)
        print(f"  {label:<12}{ip:<18}{text}")
        lines.append(f"{label} ({ip}): {text}")

    lists = [v for v in results.values() if isinstance(v, list)]
    if len(lists) > 1:
        normalized = {tuple(sorted(v)) for v in lists}
        if len(normalized) > 1:
            warning("ANSWERS DIFFER between resolvers.")
            lines.append("STATUS: answers differ")
        else:
            success("All responding resolvers agree.")
            lines.append("STATUS: consistent")
    else:
        warning("Insufficient responses to compare.")
        lines.append("STATUS: insufficient responses")
    return lines


def dnssec_check(domain):
    dns = _require("dns")
    if not dns:
        return None
    if not validate_domain(domain):
        error(f"Invalid domain: {domain}")
        return None
    import dns.resolver

    info("Querying DNSSEC records (DS, DNSKEY, RRSIG)...")
    records = {}
    for rtype in ("DS", "DNSKEY", "RRSIG"):
        try:
            ans = dns.resolver.resolve(domain, rtype, lifetime=DNS_TIMEOUT)
            records[rtype] = [rdata.to_text() for rdata in ans]
        except dns.resolver.NoAnswer:
            records[rtype] = []
        except dns.resolver.NXDOMAIN:
            records[rtype] = []
            break
        except dns.resolver.LifetimeTimeout:
            records[rtype] = "TIMEOUT"
        except Exception:
            records[rtype] = "ERROR"

    section(f"DNSSEC - {domain}")
    lines = []
    for rtype, value in records.items():
        if isinstance(value, list):
            count = len(value)
            state = f"{count} record(s)" if count else "none"
        else:
            state = value
        print(f"  {rtype:<8}: {state}")
        lines.append(f"{rtype}: {state}")

    ds = records.get("DS") or []
    dnskey = records.get("DNSKEY") or []
    rrsig = records.get("RRSIG") or []

    if isinstance(ds, list) and isinstance(dnskey, list):
        if not ds and not dnskey:
            print(f"  Status   : DNSSEC not configured")
            lines.append("Status: not configured")
        elif ds and dnskey:
            print(f"  Status   : DNSSEC configured (records present)")
            print(f"  Validated: no - this tool does not perform full chain validation")
            lines.append("Status: configured (records present, NOT validated)")
            warning("Presence of DS/DNSKEY does not prove cryptographic validity.")
        else:
            print(f"  Status   : partial/inconsistent")
            lines.append("Status: partial DNSSEC data")
            warning("Partial DNSSEC records - configuration may be broken.")

    if rrsig:
        section(f"RRSIG sample ({len(rrsig)} records)")
        for rec in rrsig[:3]:
            print(f"  {rec[:100]}{'...' if len(rec) > 100 else ''}")
    return lines


def subnet_calculator(cidr):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except (ValueError, TypeError):
        error(f"Invalid CIDR: {cidr}")
        return None

    section(f"Subnet - {net}")
    lines = [
        f"Version          : IPv{net.version}",
        f"Network address  : {net.network_address}",
        f"Prefix length    : /{net.prefixlen}",
        f"Total addresses  : {net.num_addresses}",
    ]
    if net.version == 4:
        lines.append(f"Netmask          : {net.netmask}")
        lines.append(f"Wildcard mask    : {net.hostmask}")
        lines.append(f"Broadcast        : {net.broadcast_address}")
        if net.prefixlen <= 30:
            first = net.network_address + 1
            last = net.broadcast_address - 1
            usable = net.num_addresses - 2
            lines.append(f"First usable     : {first}")
            lines.append(f"Last usable      : {last}")
            lines.append(f"Usable hosts     : {usable}")
        elif net.prefixlen == 31:
            lines.append(f"First usable     : {net.network_address}")
            lines.append(f"Last usable      : {net.broadcast_address}")
            lines.append("Note             : /31 point-to-point (RFC 3021)")
        else:
            lines.append(f"Host address     : {net.network_address}")
            lines.append("Note             : /32 single host")
    else:
        if net.prefixlen <= 127:
            lines.append(f"First address    : {net.network_address + 1}")
            lines.append(f"Last address     : {net.broadcast_address - 1}")

    for ln in lines:
        print(f"  {ln}")
    return lines


def ip_reputation_check(target):
    """Optional AbuseIPDB lookup; never fabricates a score without an API key."""
    parsed = parse_ip((target or "").strip())
    if not parsed or not parsed.is_global:
        error("Enter a valid public IP address for reputation lookup.")
        return None
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        warning("IP reputation needs ABUSEIPDB_API_KEY. Set it as an environment variable; no query was sent.")
        return ["Status: not queried", "Reason: ABUSEIPDB_API_KEY is not configured"]
    requests = _require("requests")
    if not requests:
        return None
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": str(parsed), "maxAgeInDays": "90"},
            headers={"Accept": "application/json", "Key": api_key},
            timeout=API_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json().get("data", {})
        lines = [f"IP: {data.get('ipAddress', parsed)}",
                 f"Abuse confidence score: {data.get('abuseConfidenceScore', 'N/A')}",
                 f"Reports: {data.get('totalReports', 'N/A')}",
                 f"Last reported: {data.get('lastReportedAt', 'N/A')}",
                 "Source: AbuseIPDB; reputation may be incomplete or inaccurate"]
        section(f"IP reputation - {parsed}")
        for line in lines:
            print("  " + line)
        return lines
    except Exception as exc:
        error(f"Reputation lookup failed: {type(exc).__name__}")
        return [f"Lookup error: {type(exc).__name__}"]


def email_domain_security(domain, dkim_selector=None):
    """Inspect public MX/SPF/DMARC records and DKIM only for a supplied selector."""
    dns = _require("dns")
    if not dns:
        return None
    if not validate_domain(domain):
        error(f"Invalid domain: {domain}")
        return None
    import dns.resolver
    domain = domain.rstrip(".").encode("idna").decode("ascii").lower()
    queries = [("MX", domain, "MX"), ("SPF", domain, "TXT"), ("DMARC", f"_dmarc.{domain}", "TXT")]
    if dkim_selector:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,63}", dkim_selector):
            error("Invalid DKIM selector.")
            return None
        queries.append(("DKIM", f"{dkim_selector}._domainkey.{domain}", "TXT"))
    lines = []
    section(f"Email domain security - {domain}")
    for label, name, rtype in queries:
        try:
            answer = dns.resolver.resolve(name, rtype, lifetime=DNS_TIMEOUT)
            records = [r.to_text().strip('"') for r in answer]
            if label == "SPF":
                spf = [r for r in records if r.lower().startswith("v=spf1")]
                if not spf:
                    state = "No SPF record found"
                elif len(spf) > 1:
                    state = "WARNING: multiple SPF records"
                else:
                    state = spf[0]
            else:
                state = "; ".join(records) if records else "No records found"
            lines.append(f"{label}: {state}")
        except dns.resolver.NXDOMAIN:
            lines.append(f"{label}: domain/name does not exist")
        except dns.resolver.NoAnswer:
            lines.append(f"{label}: no records found")
        except dns.resolver.LifetimeTimeout:
            lines.append(f"{label}: timeout (unknown, not confirmed missing)")
        except Exception as exc:
            lines.append(f"{label}: lookup error ({type(exc).__name__})")
    for line in lines:
        print("  " + line)
    print("  Note: this is a basic DNS configuration check, not a full security audit.")
    lines.append("Note: basic DNS inspection only; not a full security audit.")
    return lines


def http_response_diagnostics(target):
    requests = _require("requests")
    if not requests:
        return None
    url = normalize_url(target)
    if not url:
        error("Invalid URL. Only valid HTTP/HTTPS URLs are accepted.")
        return None
    parsed = urlparse(url)
    if parsed.hostname and (parsed.hostname.lower() == "localhost" or parsed.hostname.endswith(".localhost")):
        error("Localhost targets are not supported by this diagnostic.")
        return None
    start = time.monotonic()
    try:
        response = requests.get(url, timeout=API_TIMEOUT, allow_redirects=True, stream=True,
                                headers={"User-Agent": f"{TOOL_NAME}/{VERSION}"})
        try:
            # Avoid consuming unbounded response bodies.
            sample = response.raw.read(1024, decode_content=True) if getattr(response, "raw", None) else b""
            del sample
            elapsed = time.monotonic() - start
            lines = [f"Final status: {response.status_code}", f"Final URL: {response.url}",
                     f"Redirect count: {len(response.history)}", f"Response time: {elapsed:.3f}s",
                     f"Content-Type: {response.headers.get('Content-Type', 'N/A')}",
                     f"HTTPS used: {'yes' if urlparse(response.url).scheme == 'https' else 'no'}"]
            for index, prior in enumerate(response.history, 1):
                lines.append(f"Redirect {index}: {prior.status_code} -> {prior.headers.get('Location', 'N/A')}")
            for key in ("Server", "Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"):
                if key in response.headers:
                    lines.append(f"{key}: {response.headers[key]}")
            section("HTTP response diagnostics")
            for line in lines:
                print("  " + line)
            return lines
        finally:
            response.close()
    except Exception as exc:
        error(f"HTTP diagnostics failed: {type(exc).__name__}")
        return [f"HTTP diagnostics error: {type(exc).__name__}"]


def local_network_information():
    lines = [f"Hostname: {socket.gethostname()}"]
    addresses = set()
    try:
        for item in socket.getaddrinfo(socket.gethostname(), None):
            address = item[4][0].split("%", 1)[0]
            if address and not address.startswith("127.") and address != "::1":
                addresses.add(address)
    except OSError:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("192.0.2.1", 80))
            candidate = sock.getsockname()[0]
            if candidate and not candidate.startswith("127."):
                addresses.add(candidate)
    except OSError:
        pass
    lines.append("Local addresses: " + (", ".join(sorted(addresses)) if addresses else "unavailable"))
    lines.append("Gateway: not detected by portable standard-library method")
    section("Local network information")
    for line in lines:
        print("  " + line)
    return lines


def dns_ttl_cache_inspector(domain, rtype):
    dns = _require("dns")
    if not dns:
        return None
    if not validate_domain(domain):
        error(f"Invalid domain: {domain}")
        return None
    rtype = (rtype or "A").upper().strip()
    if rtype not in DNS_RECORD_TYPES:
        error(f"Unsupported record type: {rtype}")
        return None
    import dns.resolver
    lines = []
    started = time.monotonic()
    try:
        answer = dns.resolver.resolve(domain, rtype, lifetime=DNS_TIMEOUT)
        elapsed = time.monotonic() - started
        lines.append(f"Resolver: system-configured resolver")
        lines.append(f"Query time: {elapsed:.3f}s")
        lines.append(f"TTL: {answer.rrset.ttl} seconds")
        lines.extend(f"Answer: {record.to_text()}" for record in answer)
    except dns.resolver.NXDOMAIN:
        lines.append("Status: NXDOMAIN")
    except dns.resolver.NoAnswer:
        lines.append("Status: NO DATA")
    except dns.resolver.LifetimeTimeout:
        lines.append("Status: TIMEOUT")
    except Exception as exc:
        lines.append(f"Status: ERROR ({type(exc).__name__})")
    section(f"DNS TTL & cache - {domain} {rtype}")
    for line in lines:
        print("  " + line)
    print("  Note: TTL is resolver response metadata; this does not inspect every global cache.")
    lines.append("Note: does not inspect every global cache.")
    return lines


def _safe_http_target(target):
    normalized = normalize_url(target)
    if not normalized:
        return None
    return normalized


def cdn_waf_detector(target):
    url = _safe_http_target(target)
    if not url:
        return ["Error: invalid target URL"]
    response = None
    try:
        response = _require("requests").get(
            url, timeout=API_TIMEOUT, allow_redirects=False, stream=True,
            headers={"User-Agent": f"{TOOL_NAME}/{VERSION}"}
        )
        evidence = []
        checks = {
            "Cloudflare": ("cf-ray", "cf-cache-status", "cloudflare"),
            "Akamai": ("akamai", "akamai-grn", "x-akamai-transformed"),
            "Fastly": ("fastly", "x-served-by", "x-cache-hits"),
            "Amazon CloudFront": ("cloudfront", "x-amz-cf-id", "x-amz-cf-pop"),
            "Imperva / Incapsula": ("incap_ses", "visid_incap", "x-iinfo"),
            "Sucuri": ("sucuri", "x-sucuri-id", "x-sucuri-cache"),
        }
        combined = " ".join(f"{k}: {v}" for k, v in response.headers.items()).lower()
        for vendor, tokens in checks.items():
            if any(token in combined for token in tokens):
                evidence.append(f"Possible {vendor} CDN/WAF indicators")
        if not evidence:
            evidence.append("No recognizable CDN/WAF header indicators found")
        lines = [f"URL: {response.url}", f"HTTP status: {response.status_code}", *evidence,
                 "Note: header fingerprinting is indicative, not proof; providers may hide headers."]
    except Exception as exc:
        lines = [f"Request failed: {type(exc).__name__}: {exc}"]
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass
    section(f"CDN / WAF detector - {target}")
    for line in lines:
        print("  " + line)
    return lines


def redirect_chain_analyzer(target):
    url = _safe_http_target(target)
    if not url:
        return ["Error: invalid target URL"]
    lines = []
    response = None
    try:
        response = _require("requests").get(
            url, timeout=API_TIMEOUT, allow_redirects=True,
            headers={"User-Agent": f"{TOOL_NAME}/{VERSION}"}, stream=True
        )
        history = list(response.history)
        for i, item in enumerate(history, 1):
            lines.append(f"Hop {i}: {item.status_code} {item.url} -> {item.headers.get('Location', '(missing Location)')}")
        lines.append(f"Final: {response.status_code} {response.url}")
        lines.append(f"Redirect count: {len(history)}")
    except Exception as exc:
        lines.append(f"Request failed: {type(exc).__name__}: {exc}")
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass
    section(f"Redirect chain - {target}")
    for line in lines:
        print("  " + line)
    return lines


def http_performance_breakdown(target):
    url = _safe_http_target(target)
    if not url:
        return ["Error: invalid target URL"]
    lines = []
    response = None
    try:
        started = time.perf_counter()
        response = _require("requests").get(
            url, timeout=API_TIMEOUT, allow_redirects=True,
            headers={"User-Agent": f"{TOOL_NAME}/{VERSION}"}, stream=True
        )
        headers_done = time.perf_counter()
        size = 0
        for chunk in response.iter_content(chunk_size=16384):
            size += len(chunk)
            if size >= 1024 * 1024:
                break
        body_done = time.perf_counter()
        lines = [f"Final URL: {response.url}", f"Status: {response.status_code}",
                 f"Redirects: {len(response.history)}", f"Request to headers: {(headers_done-started)*1000:.1f} ms",
                 f"First body-read window: {(body_done-headers_done)*1000:.1f} ms",
                 f"Bytes sampled: {size}", "Note: timings include network and client overhead; body sample capped at 1 MiB."]
    except Exception as exc:
        lines.append(f"Request failed: {type(exc).__name__}: {exc}")
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass
    section(f"HTTP performance - {target}")
    for line in lines:
        print("  " + line)
    return lines


def certificate_transparency_lookup(domain):
    domain = (domain or "").strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]
    if not validate_domain(domain):
        return ["Error: invalid domain"]
    import json
    max_response_bytes = 4 * 1024 * 1024
    response = None
    try:
        response = _require("requests").get(
            "https://crt.sh/", params={"q": f"%.{domain}", "output": "json"},
            timeout=API_TIMEOUT, headers={"User-Agent": f"{TOOL_NAME}/{VERSION}"}, stream=True
        )
        response.raise_for_status()
        payload = bytearray()
        for chunk in response.iter_content(chunk_size=65536):
            if not chunk:
                continue
            payload.extend(chunk)
            if len(payload) > max_response_bytes:
                raise ValueError("response exceeded 4 MiB safety limit")
        records = json.loads(payload.decode("utf-8"))
        if not isinstance(records, list):
            raise ValueError("response was not a JSON list")
        seen = set()
        for item in records:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name_value", "")).strip()
            if name:
                for value in name.splitlines():
                    value = value.strip().lower()
                    if value and value not in seen:
                        seen.add(value)
                        if len(seen) >= 100:
                            break
            if len(seen) >= 100:
                break
        lines = [f"Unique certificate names returned: {len(seen)}", *sorted(seen),
                 "Note: public CT log results can include historical or expired certificates; capped at 100 names and 4 MiB of response data."]
    except Exception as exc:
        lines = [f"Lookup failed: {type(exc).__name__}: {exc}"]
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass
    section(f"Certificate Transparency - {domain}")
    for line in lines:
        print("  " + line)
    return lines


def security_headers_analyzer(target):
    url=_safe_http_target(target)
    if not url: return ["Error: invalid target URL"]
    expected={"strict-transport-security":"HSTS", "content-security-policy":"CSP",
              "x-content-type-options":"X-Content-Type-Options", "x-frame-options":"X-Frame-Options",
              "referrer-policy":"Referrer-Policy", "permissions-policy":"Permissions-Policy"}
    try:
        response=_require("requests").get(url, timeout=API_TIMEOUT, allow_redirects=True, stream=True,
                                          headers={"User-Agent": f"{TOOL_NAME}/{VERSION}"})
        headers={k.lower():v for k,v in response.headers.items()}
        lines=[f"Final URL: {response.url}", f"HTTP status: {response.status_code}"]
        for key,label in expected.items(): lines.append(f"{label}: {headers.get(key, 'MISSING')}")
        lines.append("Note: missing headers are review signals, not automatically vulnerabilities.")
        response.close()
    except Exception as exc: lines=[f"Request failed: {type(exc).__name__}: {exc}"]
    section(f"Security headers - {target}")
    for line in lines: print("  "+line)
    return lines


def latency_route_diagnostics(target):
    host=(target or "").strip()
    if host.startswith(("http://", "https://")):
        try:
            parsed_url = urlparse(host)
            _ = parsed_url.port
            host = parsed_url.hostname or ""
        except ValueError:
            return ["Error: invalid target URL"]
    if not host or any(c.isspace() for c in host): return ["Error: invalid host"]
    try:
        parsed=ipaddress.ip_address(host)
        address=str(parsed)
    except ValueError:
        if not validate_domain(host): return ["Error: invalid host"]
        try: address=socket.gethostbyname(host)
        except OSError as exc: return [f"DNS resolution failed: {exc}"]
    lines=[f"Host: {host}", f"Resolved address: {address}"]
    samples=[]
    for index in range(4):
        started=time.perf_counter()
        try:
            with socket.create_connection((address, 443), timeout=2):
                samples.append((time.perf_counter()-started)*1000)
        except OSError as exc:
            lines.append(f"TCP/443 sample {index+1}: failed ({type(exc).__name__})")
        time.sleep(0.1)
    if samples:
        lines.extend([f"TCP/443 successful samples: {len(samples)}/4", f"Min: {min(samples):.1f} ms",
                      f"Average: {sum(samples)/len(samples):.1f} ms", f"Max: {max(samples):.1f} ms"])
    lines.append("Note: measures TCP connection time to port 443, not ICMP ping or a full traceroute.")
    section(f"Latency diagnostics - {host}")
    for line in lines: print("  "+line)
    return lines


def dns_health_checker(domain):
    domain=(domain or "").strip().rstrip(".")
    if not validate_domain(domain): return ["Error: invalid domain"]
    lines=[]
    try:
        import dns.resolver
        resolver=dns.resolver.Resolver()
        resolver.timeout=DNS_TIMEOUT
        resolver.lifetime=DNS_TIMEOUT
        for rtype in ("A", "AAAA", "MX", "NS", "SOA", "TXT"):
            started=time.perf_counter()
            try:
                answer=resolver.resolve(domain, rtype)
                elapsed=(time.perf_counter()-started)*1000
                values=[r.to_text() for r in answer[:5]]
                lines.append(f"{rtype}: OK ({elapsed:.1f} ms, TTL {answer.rrset.ttl}) - {'; '.join(values)}")
            except dns.resolver.NXDOMAIN: lines.append(f"{rtype}: NXDOMAIN")
            except dns.resolver.NoAnswer: lines.append(f"{rtype}: no records")
            except dns.resolver.LifetimeTimeout: lines.append(f"{rtype}: timeout")
            except Exception as exc: lines.append(f"{rtype}: error ({type(exc).__name__})")
    except ImportError: lines=["Missing dependency: dnspython"]
    section(f"DNS health check - {domain}")
    for line in lines: print("  "+line)
    return lines


def smart_diagnostic_report(target):
    value=(target or "").strip()
    if not value: return ["Error: target required"]
    lines=[f"Target: {value}", f"Timestamp: {datetime.datetime.now().isoformat()}"]
    try:
        parsed = urlparse(value if "://" in value else "https://" + value)
        _ = parsed.port
    except ValueError:
        return ["Error: invalid target URL"]
    host = parsed.hostname or value
    if validate_domain(host):
        try:
            addresses=sorted({x[4][0] for x in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})
            lines.append("DNS: resolved - "+", ".join(addresses[:8]))
        except OSError as exc: lines.append(f"DNS: resolution failed ({type(exc).__name__})")
    elif validate_ip(host): lines.append(f"IP syntax: valid ({host})")
    else: lines.append("Target syntax: could not classify as domain/IP/URL")
    if parsed.scheme in ("http", "https") and (parsed.netloc or validate_domain(host) or validate_ip(host)):
        response = None
        try:
            url=_safe_http_target(value)
            if url:
                started=time.perf_counter()
                response=_require("requests").get(url, timeout=API_TIMEOUT, allow_redirects=True, stream=True,
                                                  headers={"User-Agent": f"{TOOL_NAME}/{VERSION}"})
                lines.extend([f"HTTP: {response.status_code}", f"Final URL: {response.url}",
                              f"Redirects: {len(response.history)}", f"Time to headers: {(time.perf_counter()-started)*1000:.1f} ms"])
                for key in ("content-type", "server", "strict-transport-security", "content-security-policy"):
                    lines.append(f"Header {key}: {response.headers.get(key, 'not present')}")
        except Exception as exc:
            lines.append(f"HTTP: request failed ({type(exc).__name__})")
        finally:
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass
    lines.append("This report is a quick triage summary, not a full security audit.")
    section(f"Smart diagnostic report - {target}")
    for line in lines: print("  "+line)
    return lines


def dns_query_comparison(domain, rtype):
    """Compare a DNS record across the application's existing public resolvers."""
    dns = _require("dns")
    if not dns:
        return None
    domain = (domain or "").strip().rstrip(".")
    rtype = (rtype or "A").upper().strip()
    if not validate_domain(domain):
        return ["Error: invalid domain"]
    if rtype not in DNS_RECORD_TYPES:
        return [f"Error: unsupported record type ({', '.join(DNS_RECORD_TYPES)})"]
    results = {}
    threads = []
    for _name, resolver_ip in PUBLIC_RESOLVERS:
        thread = threading.Thread(
            target=_query_resolver, args=(resolver_ip, domain, rtype, results), daemon=True
        )
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join(timeout=DNS_TIMEOUT + 1)
    lines = [f"Domain: {domain}", f"Record type: {rtype}"]
    usable = []
    for name, resolver_ip in PUBLIC_RESOLVERS:
        value = results.get(resolver_ip, "NO RESPONSE")
        if isinstance(value, list):
            rendered = ", ".join(value) if value else "(no records)"
            usable.append(tuple(value))
        else:
            rendered = value
        lines.append(f"{name} ({resolver_ip}): {rendered}")
    if len(usable) >= 2:
        lines.append("Comparison: " + ("answers agree" if len(set(usable)) == 1 else "answers differ"))
    else:
        lines.append("Comparison: insufficient successful answers")
    section(f"DNS query comparison - {domain} {rtype}")
    for line in lines:
        print("  " + line)
    return lines


def route_diagnostics(target):
    """Run a bounded OS traceroute utility when available; never invokes a shell."""
    host = (target or "").strip()
    if not host or any(ch.isspace() for ch in host) or not (validate_domain(host) or validate_ip(host)):
        return ["Error: enter a valid domain or IP address"]
    lines = [f"Target: {host}", "Hop limit: 12", "Probe count: 1 per hop"]
    try:
        if os.name == "nt":
            executable = shutil.which("tracert")
            command = [executable, "-d", "-h", "12", "-w", "1000", host] if executable else None
        else:
            executable = shutil.which("traceroute")
            tracepath = shutil.which("tracepath")
            if executable:
                command = [executable, "-n", "-m", "12", "-w", "1", "-q", "1", host]
            elif tracepath:
                command = [tracepath, "-m", "12", host]
            else:
                command = None
        if not command:
            lines.append("Unavailable: traceroute/tracepath utility is not installed.")
            if "com.termux" in os.environ.get("PREFIX", ""):
                lines.append("Termux: install with `pkg install traceroute`.")
            else:
                lines.append("Install a traceroute utility using your operating system's package manager.")
        else:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=18, check=False)
            output = (completed.stdout or completed.stderr or "(no output)").strip().splitlines()
            lines.extend(output[:18])
            lines.append(f"Exit code: {completed.returncode}")
    except subprocess.TimeoutExpired:
        lines.append("Stopped: traceroute exceeded the 18-second time limit.")
    except OSError as exc:
        lines.append(f"Traceroute failed: {type(exc).__name__}")
    lines.append("Note: routes can hide hops or show timeouts; this is not a port scan.")
    section(f"Route diagnostics - {host}")
    for line in lines:
        print("  " + line)
    return lines


def connection_stability_monitor(target, port=443, samples=5, interval=2):
    """Low-rate TCP connection checks to one host and one port."""
    host = (target or "").strip()
    if host.startswith(("http://", "https://")):
        try:
            parsed_url = urlparse(host)
            _ = parsed_url.port
            host = parsed_url.hostname or ""
        except ValueError:
            return ["Error: invalid target URL"]
    if not (validate_domain(host) or validate_ip(host)):
        return ["Error: enter a valid domain or IP address"]
    try:
        port = int(port)
        samples = int(samples)
        interval = float(interval)
    except (TypeError, ValueError):
        return ["Error: port, samples, or interval is invalid"]
    if not 1 <= port <= 65535 or not 1 <= samples <= 30 or not 1 <= interval <= 10:
        return ["Error: port 1-65535, samples 1-30, interval 1-10 seconds"]
    checks = []
    for index in range(samples):
        started = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=3):
                checks.append((True, (time.perf_counter() - started) * 1000, "connected"))
        except OSError as exc:
            checks.append((False, (time.perf_counter() - started) * 1000, type(exc).__name__))
        if index + 1 < samples:
            time.sleep(interval)
    successful = [elapsed for ok, elapsed, _detail in checks if ok]
    lines = [f"Target: {host}:{port}", f"Samples: {samples}", f"Successful: {len(successful)}/{samples}",
             f"Success rate: {len(successful) / samples * 100:.1f}%"]
    if successful:
        lines.extend([f"Min TCP connect: {min(successful):.1f} ms",
                      f"Average TCP connect: {sum(successful) / len(successful):.1f} ms",
                      f"Max TCP connect: {max(successful):.1f} ms"])
    lines.extend(f"Sample {i}: {'OK' if ok else 'FAIL'} ({elapsed:.1f} ms; {detail})"
                 for i, (ok, elapsed, detail) in enumerate(checks, 1))
    lines.append("Note: this measures TCP connection stability, not ICMP latency or application health.")
    section(f"Connection stability - {host}:{port}")
    for line in lines:
        print("  " + line)
    return lines


def tls_compatibility_check(target, port=443):
    """Test individual TLS protocol handshakes without sending HTTP requests."""
    host = (target or "").strip()
    if host.startswith(("http://", "https://")):
        try:
            parsed_url = urlparse(host)
            _ = parsed_url.port
            host = parsed_url.hostname or ""
        except ValueError:
            return ["Error: invalid target URL"]
    if not (validate_domain(host) or validate_ip(host)):
        return ["Error: enter a valid domain or IP address"]
    try:
        port = int(port)
    except (TypeError, ValueError):
        return ["Error: invalid port"]
    if not 1 <= port <= 65535:
        return ["Error: port must be between 1 and 65535"]
    tls_versions = [
        ("TLSv1", getattr(ssl.TLSVersion, "TLSv1", None)),
        ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
        ("TLSv1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
        ("TLSv1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
    ]
    lines = [f"Target: {host}:{port}", f"OpenSSL: {ssl.OPENSSL_VERSION}"]
    for label, version in tls_versions:
        if version is None:
            lines.append(f"{label}: unavailable in this Python/OpenSSL build")
            continue
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = version
            context.maximum_version = version
            with socket.create_connection((host, port), timeout=3) as raw_sock:
                with context.wrap_socket(raw_sock, server_hostname=host if not validate_ip(host) else None) as tls_sock:
                    negotiated = tls_sock.version() or label
            lines.append(f"{label}: negotiated ({negotiated})")
        except (OSError, ssl.SSLError, ValueError) as exc:
            lines.append(f"{label}: not negotiated ({type(exc).__name__})")
    lines.append("Warning: certificate verification is disabled for this compatibility probe; this is not a certificate-validity check.")
    lines.append("Note: a failure can mean server policy, network filtering, or local OpenSSL restrictions.")
    section(f"TLS compatibility - {host}:{port}")
    for line in lines:
        print("  " + line)
    return lines


def http_method_checker(target):
    """Send only an OPTIONS request and report the server's Allow response header."""
    url = _safe_http_target(target)
    if not url:
        return ["Error: invalid target URL"]
    requests = _require("requests")
    if not requests:
        return None
    try:
        response = requests.options(url, timeout=API_TIMEOUT, allow_redirects=False,
                                    headers={"User-Agent": f"{TOOL_NAME}/{VERSION}"})
        lines = [f"URL: {url}", f"HTTP status: {response.status_code}",
                 f"Allow header: {response.headers.get('Allow', '(not supplied)')}",
                 f"Access-Control-Allow-Methods: {response.headers.get('Access-Control-Allow-Methods', '(not supplied)')}",
                 "Only OPTIONS was sent; this tool does not attempt state-changing methods."]
        response.close()
    except Exception as exc:
        lines = [f"Request failed: {type(exc).__name__}: {exc}"]
    section(f"HTTP method checker - {target}")
    for line in lines:
        print("  " + line)
    return lines


def ipv6_readiness_check(domain):
    """Resolve and make one bounded HTTPS-port connection attempt over IPv6."""
    domain = (domain or "").strip().rstrip(".")
    if not validate_domain(domain):
        return ["Error: enter a valid domain (not an IP address)"]
    lines = [f"Domain: {domain}"]
    try:
        infos = socket.getaddrinfo(domain, 443, socket.AF_INET6, socket.SOCK_STREAM)
        addresses = list(dict.fromkeys(info[4][0] for info in infos))
    except socket.gaierror as exc:
        lines.extend(["AAAA / IPv6 resolution: unavailable", f"Reason: {type(exc).__name__}"])
        lines.append("Status: IPv6 readiness could not be confirmed.")
        section(f"IPv6 readiness - {domain}")
        for line in lines:
            print("  " + line)
        return lines
    lines.append("IPv6 addresses: " + ", ".join(addresses[:8]))
    connected = False
    for address in addresses[:2]:
        try:
            with socket.create_connection((address, 443, 0, 0), timeout=3):
                connected = True
                lines.append(f"TCP/443 over IPv6: connected to {address}")
                break
        except OSError as exc:
            lines.append(f"TCP/443 to {address}: failed ({type(exc).__name__})")
    lines.append("Status: IPv6 path reachable" if connected else "Status: AAAA exists, but IPv6 connection was not confirmed")
    section(f"IPv6 readiness - {domain}")
    for line in lines:
        print("  " + line)
    return lines


def _local_data_dir():
    return os.path.join(os.path.expanduser("~"), ".ip-finder")


def _load_local_json(filename, default):
    path = os.path.join(_local_data_dir(), filename)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            value = __import__("json").load(handle)
        return value if isinstance(value, type(default)) else default
    except (OSError, ValueError, TypeError):
        return default


def _save_local_json(filename, value):
    import json
    directory = _local_data_dir()
    os.makedirs(directory, mode=0o700, exist_ok=True)
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass
    path = os.path.join(directory, filename)
    temp_path = path + ".tmp"
    with open(temp_path, "w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    try:
        os.chmod(temp_path, 0o600)
    except OSError:
        pass
    os.replace(temp_path, path)
    return path


def historical_results():
    """Save the current session, view prior snapshots, or compare two snapshots."""
    import json
    history = _load_local_json("session_history.json", [])
    # Ignore malformed entries so one damaged local record does not disable history.
    history = [item for item in history if isinstance(item, dict)]
    section("Historical results")
    print("  1. Save current session snapshot")
    print("  2. View saved snapshots")
    print("  3. Compare two snapshots")
    choice = ask("Select [1-3]")
    if choice == "1":
        if RESULTS.empty():
            return ["No current session results to save"]
        snapshot = {"timestamp": datetime.datetime.now().isoformat(),
                    "sections": [{"title": title, "lines": lines} for title, lines in RESULTS.sections]}
        history.append(snapshot)
        history = history[-50:]
        try:
            path = _save_local_json("session_history.json", history)
            lines = [f"Saved snapshot #{len(history)}", f"Storage: {path}", "Maximum retained snapshots: 50"]
        except OSError as exc:
            lines = [f"Save failed: {type(exc).__name__}: {exc}"]
    elif choice == "2":
        lines = [f"Saved snapshots: {len(history)}"]
        lines.extend(
            f"#{index} {item.get('timestamp', 'unknown')} — "
            f"{len(item.get('sections', [])) if isinstance(item.get('sections', []), list) else 0} section(s)"
            for index, item in enumerate(history, 1)
        )
        if not history:
            lines.append("No snapshots yet; save a session after running one or more tools.")
    elif choice == "3":
        if len(history) < 2:
            lines = ["At least two saved snapshots are needed for comparison."]
        else:
            print("  Available snapshots:")
            for index, item in enumerate(history, 1):
                print(f"  #{index} {item.get('timestamp', 'unknown')}")
            try:
                first = int(ask("Older snapshot number"))
                second = int(ask("Newer snapshot number"))
                if first < 1 or second < 1 or first > len(history) or second > len(history) or first == second:
                    raise ValueError
                a, b = history[first - 1], history[second - 1]
                def normalize(item):
                    entries = item.get("sections", [])
                    if not isinstance(entries, list):
                        return {}
                    return {entry.get("title", ""): entry.get("lines", [])
                            for entry in entries if isinstance(entry, dict)}
                old, new = normalize(a), normalize(b)
                titles = sorted(set(old) | set(new))
                lines = [f"Comparing #{first} ({a.get('timestamp')}) to #{second} ({b.get('timestamp')})"]
                for title in titles:
                    if old.get(title) == new.get(title):
                        lines.append(f"UNCHANGED: {title}")
                    elif title not in old:
                        lines.append(f"ADDED: {title}")
                    elif title not in new:
                        lines.append(f"REMOVED: {title}")
                    else:
                        lines.append(f"CHANGED: {title}")
            except (ValueError, TypeError):
                lines = ["Invalid snapshot number selection."]
    else:
        lines = ["Cancelled: choose 1, 2, or 3."]
    for line in lines:
        print("  " + line)
    return lines


def batch_domain_checker(filepath):
    """Resolve a user-supplied list of domains (DNS only; bounded to 50 lines)."""
    dns = _require("dns")
    if not dns:
        return None
    filepath = (filepath or "").strip()
    if not filepath:
        return ["Error: file path is required"]
    try:
        if os.path.getsize(filepath) > 1024 * 1024:
            return ["Error: input file exceeds 1 MiB"]
        with open(filepath, "r", encoding="utf-8-sig") as handle:
            raw_domains = [line.strip() for line in handle if line.strip() and not line.strip().startswith("#")]
    except OSError as exc:
        return [f"Could not read file: {type(exc).__name__}: {exc}"]
    unique = list(dict.fromkeys(raw_domains))
    if len(unique) > 50:
        return [f"Error: file has {len(unique)} domains; maximum is 50 per run"]
    invalid = [domain for domain in unique if not validate_domain(domain.rstrip("."))]
    domains = [domain.rstrip(".") for domain in unique if validate_domain(domain.rstrip("."))]
    if not domains:
        return ["No valid domains found in the file"]
    from concurrent.futures import ThreadPoolExecutor
    import dns.resolver

    def inspect_domain(domain):
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1.5
        resolver.lifetime = 1.5
        found = []
        for rtype in ("A", "AAAA"):
            try:
                answer = resolver.resolve(domain, rtype, lifetime=1.5)
                found.extend(f"{rtype}={record.to_text()}" for record in list(answer)[:4])
            except dns.resolver.NXDOMAIN:
                return f"{domain}: NXDOMAIN"
            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.LifetimeTimeout:
                found.append(f"{rtype}=TIMEOUT")
            except Exception as exc:
                found.append(f"{rtype}=ERROR({type(exc).__name__})")
        return f"{domain}: " + (", ".join(found) if found else "no A/AAAA answers")

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {domain: pool.submit(inspect_domain, domain) for domain in domains}
        results = [futures[domain].result() for domain in domains]
    lines = [f"Input domains: {len(unique)}", f"Valid domains: {len(domains)}", f"Invalid entries skipped: {len(invalid)}"]
    lines.extend(f"INVALID: {entry}" for entry in invalid[:10])
    lines.extend(results)
    lines.append("Safety limit: DNS lookups only, maximum 50 domains, four workers, no port scans or HTTP requests.")
    section("Batch domain checker")
    for line in lines:
        print("  " + line)
    return lines


def email_dns_deep_check(domain):
    """Inspect SPF, DMARC, MX and a small, bounded set of common DKIM selectors."""
    dns = _require("dns")
    if not dns:
        return None
    domain = (domain or "").strip().rstrip(".")
    if not validate_domain(domain):
        return ["Error: invalid domain"]
    import dns.resolver
    from concurrent.futures import ThreadPoolExecutor

    selectors = ("default", "selector1", "selector2", "google", "k1", "mail")
    def query(name, rtype):
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        try:
            answer = resolver.resolve(name, rtype, lifetime=2)
            return [record.to_text() for record in list(answer)[:8]]
        except dns.resolver.NXDOMAIN:
            return []
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.LifetimeTimeout:
            return ["TIMEOUT"]
        except Exception as exc:
            return [f"ERROR({type(exc).__name__})"]

    queries = [("MX", domain, "MX"), ("TXT", domain, "TXT"), ("DMARC", f"_dmarc.{domain}", "TXT")]
    queries.extend((f"DKIM {selector}", f"{selector}._domainkey.{domain}", "TXT") for selector in selectors)
    results = {}
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {label: pool.submit(query, name, rtype) for label, name, rtype in queries}
        for label, future in futures.items():
            results[label] = future.result()
    mx = results.get("MX", [])
    txt = results.get("TXT", [])
    dmarc = results.get("DMARC", [])

    def is_query_result(value):
        # Timeout/error markers are diagnostic statuses, not DNS records.
        return value != "TIMEOUT" and not str(value).startswith("ERROR(")

    mx_records = [record for record in mx if is_query_result(record)]
    txt_records = [record for record in txt if is_query_result(record)]
    dmarc_values = [record for record in dmarc if is_query_result(record)]
    spf = [record for record in txt_records if "v=spf1" in record.lower()]
    dmarc_records = [record for record in dmarc_values if "v=dmarc1" in record.lower()]
    lines = [f"Domain: {domain}", f"MX records: {len(mx_records)}", *[f"  {record}" for record in mx_records[:5]],
             f"SPF records found: {len(spf)}"]
    for label, values in (("MX", mx), ("TXT", txt), ("DMARC", dmarc)):
        status_values = [value for value in values if not is_query_result(value)]
        lines.extend(f"{label} lookup status: {value}" for value in status_values)
    lines.extend(f"  SPF: {record}" for record in spf)
    if len(spf) > 1:
        lines.append("WARNING: multiple SPF records can cause SPF permerror.")
    if not spf:
        lines.append("SPF: not found (or DNS lookup inconclusive)")
    lines.append(f"DMARC records found: {len(dmarc_records)}")
    for record in dmarc_records:
        policy = re.search(r"(?:^|;)\s*p\s*=\s*([^;\s]+)", record.strip().strip('"'), re.I)
        lines.append(f"  DMARC: {record}")
        lines.append(f"  DMARC policy: {policy.group(1) if policy else 'unspecified'}")
    if not dmarc_records:
        lines.append("DMARC: not found (or DNS lookup inconclusive)")
    for selector in selectors:
        answers = results.get(f"DKIM {selector}", [])
        dkim_records = [answer for answer in answers if is_query_result(answer)]
        dkim_statuses = [answer for answer in answers if not is_query_result(answer)]
        if dkim_records:
            state = "record found"
        elif dkim_statuses:
            state = "lookup inconclusive"
        else:
            state = "no TXT record returned"
        lines.append(f"DKIM selector {selector}: {state}")
        lines.extend(f"  {item[:180]}" for item in dkim_records[:1])
        lines.extend(f"  Lookup status: {item}" for item in dkim_statuses[:1])
    lines.append("Note: DKIM selectors vary by provider; common-selector checks do not prove DKIM is absent.")
    section(f"Email DNS deep check - {domain}")
    for line in lines:
        print("  " + line)
    return lines


def configuration_validator():
    """Check local runtime, dependencies, constants, and private data-directory write access."""
    ok, missing_required, missing_optional = check_dependencies()
    lines = [f"Tool: {TOOL_NAME} v{VERSION}", f"Author: {AUTHOR}",
             f"Python: {sys.version.split()[0]}", f"Platform: {sys.platform}",
             f"OpenSSL: {ssl.OPENSSL_VERSION}",
             "Required dependencies: " + ("OK" if ok else ", ".join(missing_required)),
             "Optional dependencies: " + (", ".join(missing_optional) if missing_optional else "all available"),
             f"DNS timeout: {DNS_TIMEOUT}s", f"HTTP/API timeout: {API_TIMEOUT}s", f"Port timeout: {PORT_TIMEOUT}s"]
    for name, value in (("requests", _requests), ("dnspython", _dns), ("python-whois", _whois)):
        lines.append(f"Loaded module {name}: {'yes' if value is not None else 'no'}")
    lines.append(f"Traceroute utility: {shutil.which('traceroute') or shutil.which('tracert') or 'not installed'}")
    try:
        directory = _local_data_dir()
        os.makedirs(directory, mode=0o700, exist_ok=True)
        probe = os.path.join(directory, ".write-test")
        with open(probe, "w", encoding="utf-8") as handle:
            handle.write("ok")
        os.remove(probe)
        lines.append("Private data directory write: OK")
    except OSError as exc:
        lines.append(f"Private data directory write: FAILED ({type(exc).__name__})")
    lines.append("Note: this checks local configuration only and does not contact external targets.")
    section("Configuration validator")
    for line in lines:
        print("  " + line)
    return lines


def uptime_history_monitor(target, checks=3, interval=5):
    """Run bounded, low-rate HTTP availability checks and append local history."""
    url = _safe_http_target(target)
    if not url:
        return ["Error: enter a valid target URL or domain"]
    try:
        checks = int(checks)
        interval = float(interval)
    except (TypeError, ValueError):
        return ["Error: invalid check count or interval"]
    if not 1 <= checks <= 30 or not 5 <= interval <= 60:
        return ["Error: checks must be 1-30 and interval must be 5-60 seconds"]
    requests = _require("requests")
    if not requests:
        return None
    observations = []
    for index in range(checks):
        started = time.perf_counter()
        record = {"timestamp": datetime.datetime.now().isoformat(), "target": url, "ok": False,
                  "status": None, "latency_ms": None, "error": None}
        try:
            response = requests.get(url, timeout=5, allow_redirects=False, stream=True,
                                    headers={"User-Agent": f"{TOOL_NAME}/{VERSION}"})
            record["status"] = response.status_code
            # Count an HTTP 5xx as an availability failure; 2xx-4xx indicate
            # that an HTTP endpoint responded, though a 4xx may still be app-level failure.
            record["ok"] = response.status_code < 500
            response.close()
        except Exception as exc:
            record["error"] = type(exc).__name__
        record["latency_ms"] = round((time.perf_counter() - started) * 1000, 2)
        observations.append(record)
        print(f"  [{index + 1}/{checks}] {record['timestamp']} "
              f"{'UP' if record['ok'] else 'DOWN'} status={record['status']} latency={record['latency_ms']}ms")
        if index + 1 < checks:
            time.sleep(interval)
    success_count = sum(1 for item in observations if item["ok"])
    lines = [f"Target: {url}", f"Checks: {checks}", f"Reachable HTTP responses: {success_count}/{checks}",
             f"Observed availability: {success_count / checks * 100:.1f}%",
             f"Mean request-to-headers: {sum(item['latency_ms'] for item in observations) / len(observations):.1f} ms",
             "Note: HTTP 5xx responses count as unavailable; 2xx-4xx count as an HTTP response. This is a short observation, not a long-term SLA or full page-load test."]
    history = _load_local_json("uptime_history.json", [])
    history.append({"created_at": datetime.datetime.now().isoformat(), "target": url, "checks": observations,
                    "availability_percent": round(success_count / checks * 100, 2)})
    try:
        _save_local_json("uptime_history.json", history[-100:])
        lines.append(f"Saved uptime runs: {min(len(history), 100)} (local history; maximum 100 runs)")
    except OSError as exc:
        lines.append(f"Could not save uptime history: {type(exc).__name__}")
    section(f"Uptime history - {url}")
    for line in lines:
        print("  " + line)
    return lines


def diagnostic_profiles(profile, target):
    """Run a documented preset assembled from existing, low-impact diagnostics."""
    profile = (profile or "").strip().lower()
    target = (target or "").strip()
    if profile not in {"basic", "web", "dns", "full"}:
        return ["Error: choose Basic, Web, DNS, or Full"]
    if not target:
        return ["Error: target is required"]
    try:
        parsed = urlparse(target if "://" in target else "https://" + target)
        _ = parsed.port
    except ValueError:
        return ["Error: invalid target URL"]
    if parsed.scheme not in ("http", "https"):
        return ["Error: use an HTTP/HTTPS URL or a valid domain/IP"]
    host = parsed.hostname or target
    if not (validate_domain(host) or validate_ip(host)):
        return ["Error: enter a valid domain, IP, or HTTP/HTTPS URL"]
    lines = [f"Profile: {profile.title()}", f"Target: {target}",
             f"Started: {datetime.datetime.now().isoformat()}"]
    if profile == "basic":
        if validate_ip(host):
            lines.extend([f"IP syntax: valid ({host})"])
        else:
            try:
                infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
                addresses = list(dict.fromkeys(item[4][0] for item in infos))
                lines.append("Resolved addresses: " + ", ".join(addresses[:8]))
            except OSError as exc:
                lines.append(f"DNS resolution failed: {type(exc).__name__}")
    elif profile == "dns":
        if not validate_domain(host):
            return ["Error: DNS profile requires a domain name"]
        lines.extend(dns_health_checker(host) or ["DNS health check returned no result"])
    elif profile == "web":
        url = _safe_http_target(target)
        if not url:
            return ["Error: Web profile requires an HTTP/HTTPS URL or valid domain"]
        lines.extend(http_response_diagnostics(url) or ["HTTP diagnostics returned no result"])
        lines.extend(security_headers_analyzer(url) or ["Security header check returned no result"])
    else:
        lines.extend(smart_diagnostic_report(target) or ["Smart diagnostic returned no result"])
        if validate_domain(host):
            lines.extend(dns_health_checker(host) or ["DNS health check returned no result"])
        lines.extend(grab_https_cert(host) or ["TLS certificate check returned no result"])
    lines.append("Profile note: presets use existing providers and bounded requests; results are diagnostic, not a penetration test.")
    section(f"Diagnostic profile - {profile}")
    for line in lines:
        print("  " + line)
    return lines



def export_json_results(target):
    import json
    if RESULTS.empty():
        warning("No results available to export. Perform a lookup first.")
        return
    safe=re.sub(r"[^A-Za-z0-9_.-]", "_", target or "session")
    default_name=f"{safe}_ipfinder_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    filename=ask(f"Export filename [{default_name}]") or default_name
    if os.path.exists(filename) and (ask("File exists. Overwrite? (y/n) [n]").lower() or "n") != "y":
        warning("Export cancelled."); return
    payload={"tool":TOOL_NAME,"version":VERSION,"timestamp":datetime.datetime.now().isoformat(),"target":target,
             "results":[{"title":title,"lines":lines} for title,lines in RESULTS.sections]}
    try:
        with open(filename,"w",encoding="utf-8") as fh: json.dump(payload,fh,ensure_ascii=False,indent=2)
        success(f"Saved to '{filename}'.")
    except OSError as exc: error(f"Write failed: {exc}")


def export_results(target):
    if RESULTS.empty():
        warning("No results available to export. Perform a lookup first.")
        return
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", target or "session")
    default_name = (
        f"{safe}_ipfinder_"
        f"{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    )
    filename = ask(f"Export filename [{default_name}]") or default_name
    if os.path.exists(filename):
        choice = ask(f"File exists. Overwrite? (y/n) [n]").lower() or "n"
        if choice != "y":
            warning("Export cancelled.")
            return
    try:
        with open(filename, "w", encoding="utf-8") as fh:
            fh.write(RESULTS.render(target))
        success(f"Saved to '{filename}'.")
    except OSError as exc:
        error(f"Write failed: {exc}")


def about_and_dependencies():
    section(f"{TOOL_NAME} v{VERSION}")
    print(f"  Author   : {AUTHOR}")
    print(f"  Platform : Termux / Linux / Windows")
    ok, missing_req, missing_opt = check_dependencies()
    if ok:
        success("All required dependencies present.")
    else:
        error("Missing required: " + ", ".join(missing_req))
        print(f"  pip install -r requirements.txt")
    if missing_opt:
        warning("Optional missing: " + ", ".join(missing_opt))

    section("Data sources and limits")
    print("  Geolocation / ASN  : ipwho.is (HTTPS, rate-limited)")
    print("  RDAP               : rdap.org (public bootstrap)")
    print("  DNS propagation    : Google / Cloudflare / Quad9 / OpenDNS")
    print("  WHOIS              : python-whois (registry-dependent)")
    print("\n  Responsible use: only inspect systems you own or have")
    print("  permission to test. Some providers rate-limit; retry later.")


def menu_lines():
    return [
        "[::] SELECT A NETWORK TOOL [::]",
        "",
        f"{DRED}[01]{RESET} Public IP Lookup       {DRED}[09]{RESET} TLS Certificate",
        f"{DRED}[02]{RESET} Reverse DNS            {DRED}[10]{RESET} Subdomain Discovery",
        f"{DRED}[03]{RESET} Domain to IP           {DRED}[11]{RESET} ASN / ISP Lookup",
        f"{DRED}[04]{RESET} DNS Records            {DRED}[12]{RESET} RDAP Lookup",
        f"{DRED}[05]{RESET} GeoIP Lookup           {DRED}[13]{RESET} DNS Propagation",
        f"{DRED}[06]{RESET} WHOIS Lookup           {DRED}[14]{RESET} DNSSEC Inspection",
        f"{DRED}[07]{RESET} Common Port Scan       {DRED}[15]{RESET} Subnet Calculator",
        f"{DRED}[08]{RESET} HTTP Headers",
        "",
        f"{CYAN}NEW TOOLS{RESET}",
        f"{DRED}[16]{RESET} IP Reputation Check",
        f"{DRED}[17]{RESET} Email Domain Security",
        f"{DRED}[18]{RESET} HTTP Response Diagnostics",
        f"{DRED}[19]{RESET} Local Network Information",
        f"{DRED}[20]{RESET} DNS TTL / Cache Inspector",
        f"{DRED}[21]{RESET} CDN / WAF Detector",
        f"{DRED}[22]{RESET} Redirect Chain Analyzer",
        f"{DRED}[23]{RESET} HTTP Performance Breakdown",
        f"{DRED}[24]{RESET} Certificate Transparency",
        f"{DRED}[25]{RESET} Security Headers Analyzer",
        f"{DRED}[26]{RESET} Latency Diagnostics",
        f"{DRED}[27]{RESET} DNS Health Checker",
        f"{DRED}[28]{RESET} Smart Diagnostic Report",
        f"{DRED}[29]{RESET} DNS Query Comparison",
        f"{DRED}[30]{RESET} Route Diagnostics",
        f"{DRED}[31]{RESET} Connection Stability Monitor",
        f"{DRED}[32]{RESET} TLS Compatibility Check",
        f"{DRED}[33]{RESET} HTTP Method Checker",
        f"{DRED}[34]{RESET} IPv6 Readiness Check",
        f"{DRED}[35]{RESET} Historical Results",
        f"{DRED}[36]{RESET} Batch Domain Checker",
        f"{DRED}[37]{RESET} Email DNS Deep Check",
        f"{DRED}[38]{RESET} Configuration Validator",
        f"{DRED}[39]{RESET} Uptime History Monitor",
        f"{DRED}[40]{RESET} Diagnostic Profiles",
        "",
        f"{DRED}[90]{RESET} Export TXT Report",
        f"{DRED}[91]{RESET} Export JSON Report",
        f"{DRED}[99]{RESET} About / Dependencies",
        f"{DRED}[00]{RESET} Exit",
    ]


def show_menu(dep_ok, missing_req):
    clear_screen()
    print_banner()
    if dep_ok:
        print(f"{CYAN}Status:{RESET} {GREEN}Ready{RESET}")
    else:
        print(f"{CYAN}Status:{RESET} {RED}Missing: {', '.join(missing_req)}{RESET}")
    print()
    for line in menu_lines():
        print(f"  {line}")
    print()


def _dispatch(choice):
    if choice == "01":
        ip = get_my_ip()
        if ip:
            RESULTS.add("Public IP", [ip])
    elif choice == "02":
        ip = ask("Target IP")
        res = reverse_dns_lookup(ip)
        RESULTS.add(f"Reverse DNS - {ip}", [res] if res else [])
    elif choice == "03":
        domain = ask("Target Domain")
        res = domain_to_ip(domain)
        RESULTS.add(f"Domain resolution - {domain}", res or [])
    elif choice == "04":
        domain = ask("Target Domain")
        res = lookup_dns_records(domain)
        lines = [f"{rtype}: {rec}" for rtype, recs in (res or {}).items() for rec in recs]
        RESULTS.add(f"DNS records - {domain}", lines)
    elif choice == "05":
        ip = ask("Target IP")
        res = ip_geo_info(ip)
        RESULTS.add(f"Geolocation - {ip}", res or [])
    elif choice == "06":
        target = ask("Target Domain or IP")
        res = whois_lookup(target)
        RESULTS.add(f"WHOIS - {target}", [f"{k}: {v}" for k, v in res.items()] if res else [])
    elif choice == "07":
        ip = ask("Target IP")
        res = port_scan(ip)
        RESULTS.add(f"Port scan - {ip}", res or [])
    elif choice == "08":
        target = ask("Target Domain, IP, or URL")
        res = grab_http_headers(target)
        lines = []
        if res:
            lines.append(f"status: {res['status']}")
            lines.extend(f"{k}: {v}" for k, v in res.items() if k not in ("status", "url"))
        RESULTS.add(f"HTTP headers - {target}", lines)
    elif choice == "09":
        target = ask("Target Domain or IP")
        res = grab_https_cert(target)
        RESULTS.add(f"TLS cert - {target}", res or [])
    elif choice == "10":
        domain = ask("Target Domain")
        res = subdomain_enum(domain)
        RESULTS.add(f"Subdomains - {domain}", res or [])
    elif choice == "11":
        target = ask("Target IP or Domain")
        res = asn_lookup(target)
        RESULTS.add(f"ASN / ISP - {target}", res or [])
    elif choice == "12":
        target = ask("Target IP or Domain")
        res = rdap_lookup(target)
        RESULTS.add(f"RDAP - {target}", res or [])
    elif choice == "13":
        domain = ask("Target Domain")
        rtype = ask(f"Record Type ({'/'.join(PROPAGATION_TYPES)})")
        res = dns_propagation_check(domain, rtype)
        RESULTS.add(f"DNS propagation - {domain} {rtype.upper()}", res or [])
    elif choice == "14":
        domain = ask("Target Domain")
        res = dnssec_check(domain)
        RESULTS.add(f"DNSSEC - {domain}", res or [])
    elif choice == "15":
        cidr = ask("CIDR (e.g. 192.168.1.0/24 or 2001:db8::/32)")
        res = subnet_calculator(cidr)
        RESULTS.add(f"Subnet - {cidr}", res or [])
    elif choice == "16":
        target = ask("Public IP")
        res = ip_reputation_check(target)
        RESULTS.add(f"IP reputation - {target}", res or [])
    elif choice == "17":
        domain = ask("Email domain")
        selector = ask("DKIM selector (optional, Enter to skip)")
        res = email_domain_security(domain, selector or None)
        RESULTS.add(f"Email domain security - {domain}", res or [])
    elif choice == "18":
        target = ask("HTTP/HTTPS URL")
        res = http_response_diagnostics(target)
        RESULTS.add(f"HTTP diagnostics - {target}", res or [])
    elif choice == "19":
        res = local_network_information()
        RESULTS.add("Local network information", res or [])
    elif choice == "20":
        domain = ask("Target Domain")
        rtype = ask("Record Type [A]") or "A"
        res = dns_ttl_cache_inspector(domain, rtype)
        RESULTS.add(f"DNS TTL - {domain} {rtype.upper()}", res or [])
    elif choice == "21":
        target = ask("Target Domain or URL")
        res = cdn_waf_detector(target)
        RESULTS.add(f"CDN/WAF - {target}", res or [])
    elif choice == "22":
        target = ask("Target URL")
        res = redirect_chain_analyzer(target)
        RESULTS.add(f"Redirect chain - {target}", res or [])
    elif choice == "23":
        target = ask("Target URL")
        res = http_performance_breakdown(target)
        RESULTS.add(f"HTTP performance - {target}", res or [])
    elif choice == "24":
        domain = ask("Target Domain")
        res = certificate_transparency_lookup(domain)
        RESULTS.add(f"Certificate transparency - {domain}", res or [])
    elif choice == "25":
        target = ask("Target URL")
        res = security_headers_analyzer(target)
        RESULTS.add(f"Security headers - {target}", res or [])
    elif choice == "26":
        target = ask("Target Domain or IP")
        res = latency_route_diagnostics(target)
        RESULTS.add(f"Latency diagnostics - {target}", res or [])
    elif choice == "27":
        domain = ask("Target Domain")
        res = dns_health_checker(domain)
        RESULTS.add(f"DNS health - {domain}", res or [])
    elif choice == "28":
        target = ask("Target Domain, IP, or URL")
        res = smart_diagnostic_report(target)
        RESULTS.add(f"Smart diagnostic report - {target}", res or [])
    elif choice == "29":
        domain = ask("Target Domain")
        rtype = (ask(f"Record Type ({'/'.join(DNS_RECORD_TYPES)}) [A]") or "A").upper()
        res = dns_query_comparison(domain, rtype)
        RESULTS.add(f"DNS comparison - {domain} {rtype}", res or [])
    elif choice == "30":
        target = ask("Target Domain or IP")
        res = route_diagnostics(target)
        RESULTS.add(f"Route diagnostics - {target}", res or [])
    elif choice == "31":
        target = ask("Target Domain, IP, or URL")
        port = ask("Target TCP port [443]") or "443"
        samples = ask("Samples (1-30) [5]") or "5"
        interval = ask("Interval seconds (1-10) [2]") or "2"
        res = connection_stability_monitor(target, port, samples, interval)
        RESULTS.add(f"Connection stability - {target}:{port}", res or [])
    elif choice == "32":
        target = ask("Target Domain or IP")
        port = ask("TLS TCP port [443]") or "443"
        res = tls_compatibility_check(target, port)
        RESULTS.add(f"TLS compatibility - {target}:{port}", res or [])
    elif choice == "33":
        target = ask("Target URL")
        res = http_method_checker(target)
        RESULTS.add(f"HTTP method checker - {target}", res or [])
    elif choice == "34":
        domain = ask("Target Domain")
        res = ipv6_readiness_check(domain)
        RESULTS.add(f"IPv6 readiness - {domain}", res or [])
    elif choice == "35":
        res = historical_results()
        RESULTS.add("Historical results", res or [])
    elif choice == "36":
        filepath = ask("Path to TXT file (one domain per line)")
        res = batch_domain_checker(filepath)
        RESULTS.add(f"Batch domain checker - {filepath}", res or [])
    elif choice == "37":
        domain = ask("Email Domain")
        res = email_dns_deep_check(domain)
        RESULTS.add(f"Email DNS deep check - {domain}", res or [])
    elif choice == "38":
        res = configuration_validator()
        RESULTS.add("Configuration validator", res or [])
    elif choice == "39":
        target = ask("Target URL or Domain")
        checks = ask("Checks (1-30) [3]") or "3"
        interval = ask("Interval seconds (5-60) [5]") or "5"
        res = uptime_history_monitor(target, checks, interval)
        RESULTS.add(f"Uptime history - {target}", res or [])
    elif choice == "40":
        profile = ask("Profile [Basic/Web/DNS/Full]") or "Basic"
        target = ask("Target Domain, IP, or URL")
        res = diagnostic_profiles(profile, target)
        RESULTS.add(f"Diagnostic profile {profile} - {target}", res or [])
    elif choice == "91":
        label = ask("Export target label [session]") or "session"
        export_json_results(label)
        return
    elif choice == "90":
        label = ask("Export target label [session]") or "session"
        export_results(label)
        return
    elif choice == "99":
        about_and_dependencies()
        return
    elif choice == "00":
        print(f"\n{CYAN}Goodbye.{RESET}")
        sys.exit(0)
    else:
        error(f"Unknown option: {choice}")


def run_menu_loop():
    ok, missing_req, _ = check_dependencies()
    while True:
        try:
            show_menu(ok, missing_req)
            try:
                choice = input(f"{GREEN}[~]{RESET} Select [00-99]: ").strip()
            except EOFError:
                print(f"\n{CYAN}Goodbye.{RESET}")
                return
            _dispatch(choice)
        except KeyboardInterrupt:
            print(f"\n{CYAN}Interrupted. Goodbye.{RESET}")
            return
        except Exception as exc:
            error(f"Unexpected error: {type(exc).__name__}: {exc}")
        pause()


def main():
    ok, missing_req, missing_opt = check_dependencies()
    load_optional_imports()
    if missing_opt:
        warning(f"Optional dependencies missing: {', '.join(missing_opt)}")
    if not ok:
        error("Required dependencies missing: " + ", ".join(missing_req))
        print("  pip install -r requirements.txt")
        sys.exit(1)
    run_menu_loop()


if __name__ == "__main__":
    main()