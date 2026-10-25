#!/usr/bin/env python3
"""IP-FINDER v1.0.0 - pure-stdlib network recon toolkit. Author: DevBrezz.

Dependencies: Python 3.10+ standard library ONLY.
No third-party packages. No external binaries. No shell-outs.

Layers, all hand-implemented:
  * DNS resolver    - UDP + TCP wire format, EDNS0, DNSSEC record parsing
  * HTTP client     - http.client + ssl, redirects, bounded streaming
  * WHOIS client    - IANA -> TLD -> registrar referral chain, port 43
  * TLS             - ssl module, full verification
  * Traceroute      - ICMP raw + TCP SYN via IP_RECVERR
  * Port probe      - raw socket connect_ex
"""

import base64
import datetime
import http.client
import ipaddress
import json
import os
import random
import re
import shutil
import socket
import ssl
import struct
import sys
import threading
import time
from urllib.parse import urljoin, urlparse

TOOL_NAME = "IP-FINDER"
VERSION = "1.0.0"
AUTHOR = "DevBrezz"

HTTP_TIMEOUT = 8.0
DNS_TIMEOUT = 3.0
PORT_TIMEOUT = 1.0
WHOIS_TIMEOUT = 8.0
TLS_TIMEOUT = 6.0

PUBLIC_RESOLVERS = [
    ("Google", "8.8.8.8"),
    ("Cloudflare", "1.1.1.1"),
    ("Quad9", "9.9.9.9"),
    ("OpenDNS", "208.67.222.222"),
]

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP-Proxy",
}

BANNER_PORTS = [21, 22, 23, 25, 80, 110, 143, 8080]

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "smtp", "ns1", "ns2", "blog", "vpn",
    "m", "dev", "test", "admin", "portal", "web", "server", "ns", "shop",
    "api", "staging", "beta", "demo",
]

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

DNS_TYPE_CODES = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15,
    "TXT": 16, "AAAA": 28, "SRV": 33, "DS": 43, "RRSIG": 46,
    "DNSKEY": 48, "AXFR": 252, "ANY": 255,
}
DNS_TYPE_NAMES = {v: k for k, v in DNS_TYPE_CODES.items()}
DNS_RCODES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
    4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET",
    8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE",
}

IP_RECVERR_LINUX = 11
MSG_ERRQUEUE_LINUX = 0x2000
SO_EE_ORIGIN_ICMP = 2
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_TIME_EXCEEDED = 11
ICMP_DEST_UNREACH = 3

_DOMAIN_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")

try:
    if hasattr(sys.stdout, "isatty") and sys.stdout.isatty() and os.environ.get("TERM") != "dumb":
        GREEN, YELLOW, RED, CYAN, DRED, BOLD, RESET = (
            "\033[92m", "\033[93m", "\033[91m", "\033[96m",
            "\033[38;5;124m", "\033[1m", "\033[0m",
        )
    else:
        GREEN = YELLOW = RED = CYAN = DRED = BOLD = RESET = ""
except Exception:
    GREEN = YELLOW = RED = CYAN = DRED = BOLD = RESET = ""


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
        out = [f"{TOOL_NAME} v{VERSION} Results",
               f"Timestamp: {datetime.datetime.now().isoformat()}",
               f"Target: {target}", ""]
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


def banner():
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
    print(f"{DRED}  {'=' * min(term_width() - 2, 66)}{RESET}\n")


def _status(label, color, msg):
    print(f"{color}[{label}]{RESET} {msg}")


def info(m):   _status("INFO", CYAN, m)
def ok(m):     _status("SUCCESS", GREEN, m)
def warn(m):   _status("WARNING", YELLOW, m)
def err(m):    _status("ERROR", RED, m)


def section(title):
    print(f"\n{BOLD}{CYAN}[::] {title.upper()}{RESET}")
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


def emit(title, rows, collector=None):
    section(title)
    lines = []
    for row in rows:
        if isinstance(row, tuple) and len(row) == 2:
            label, value = row
            line = f"{str(label):<16}{value}"
        elif isinstance(row, tuple):
            line = "  ".join(str(x) for x in row)
        else:
            line = str(row)
        print("  " + line)
        lines.append(line)
    if collector is not None:
        collector.add(title, lines)
    return lines


def validate_ip(value):
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except (ValueError, TypeError):
        return False


def parse_ip(value):
    try:
        return ipaddress.ip_address(str(value).strip())
    except (ValueError, TypeError):
        return None


def validate_domain(domain):
    if not isinstance(domain, str):
        return False
    domain = domain.strip().rstrip(".")
    if not domain or len(domain) > 253 or ".." in domain:
        return False
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    if not all(_DOMAIN_LABEL.fullmatch(l) for l in labels):
        return False
    return len(labels[-1]) >= 2


def normalize_url(raw):
    raw = (raw or "").strip()
    if not raw or any(c.isspace() for c in raw):
        return None
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    try:
        parsed = urlparse(raw)
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    if parsed.username or parsed.password:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    if port is not None and not (1 <= port <= 65535):
        return None
    if not (validate_ip(parsed.hostname) or validate_domain(parsed.hostname)):
        return None
    return raw


def classify_target(value):
    value = (value or "").strip()
    if not value:
        return ("invalid", None)
    if value.startswith(("http://", "https://")):
        try:
            parsed = urlparse(value)
            host = parsed.hostname
            _ = parsed.port
        except ValueError:
            return ("invalid", None)
        if not host:
            return ("invalid", None)
        value = host
    if validate_ip(value):
        return ("ip", value)
    if validate_domain(value):
        return ("domain", value.rstrip("."))
    return ("invalid", value)


class DNSError(Exception):
    pass


def _encode_qname(name):
    if name.endswith("."):
        name = name[:-1]
    if not name:
        return b"\x00"
    out = b""
    for label in name.split("."):
        try:
            raw = label.encode("idna") if not label.isascii() else label.encode("ascii")
        except UnicodeError as exc:
            raise DNSError(f"invalid label: {label}") from exc
        if not raw or len(raw) > 63:
            raise DNSError(f"invalid label length: {label}")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _decode_qname(buf, offset):
    labels = []
    start = offset
    jumped = False
    seen = set()
    while True:
        if offset >= len(buf):
            raise DNSError("truncated name")
        length = buf[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(buf):
                raise DNSError("truncated pointer")
            pointer = ((length & 0x3F) << 8) | buf[offset + 1]
            if pointer in seen or pointer >= len(buf):
                raise DNSError("compression loop")
            seen.add(pointer)
            if not jumped:
                start = offset + 2
            offset = pointer
            jumped = True
            continue
        if length > 63 or offset + 1 + length > len(buf):
            raise DNSError("invalid label")
        try:
            labels.append(buf[offset + 1:offset + 1 + length].decode("ascii"))
        except UnicodeDecodeError:
            labels.append(buf[offset + 1:offset + 1 + length].decode("utf-8", "replace"))
        offset += 1 + length
    return (".".join(labels) or "."), (start if jumped else offset)


def _dns_build_query(qname, qtype, edns_do=False):
    tid = random.getrandbits(16)
    flags = 0x0100
    arcount = 1 if edns_do else 0
    header = struct.pack("!HHHHHH", tid, flags, 1, 0, 0, arcount)
    question = _encode_qname(qname) + struct.pack("!HH", qtype, 1)
    body = header + question
    if edns_do:
        opt = b"\x00" + struct.pack("!HHIH", 41, 4096, 0x00008000, 0)
        body += opt
    return tid, body


def _dns_parse(buf, expected_id=None):
    if len(buf) < 12:
        raise DNSError("short header")
    tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", buf[:12])
    if expected_id is not None and tid != expected_id:
        raise DNSError("transaction id mismatch")
    rcode = flags & 0x0F
    tc = bool(flags & 0x0200)
    aa = bool(flags & 0x0400)

    offset = 12
    questions = []
    for _ in range(qd):
        name, offset = _decode_qname(buf, offset)
        if offset + 4 > len(buf):
            raise DNSError("short question")
        qtype, qclass = struct.unpack("!HH", buf[offset:offset + 4])
        offset += 4
        questions.append({"name": name, "type": qtype, "class": qclass})

    def read_rr():
        nonlocal offset
        name, offset = _decode_qname(buf, offset)
        if offset + 10 > len(buf):
            raise DNSError("short rr")
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", buf[offset:offset + 10])
        offset += 10
        rd_start = offset
        if offset + rdlen > len(buf):
            raise DNSError("short rdata")
        offset += rdlen
        return {"name": name, "type": rtype, "class": rclass, "ttl": ttl,
                "rdata_start": rd_start, "rdlen": rdlen}

    answers = [read_rr() for _ in range(an)]
    authority = [read_rr() for _ in range(ns)]
    additional = [read_rr() for _ in range(ar)]

    def decode_value(rr):
        t = rr["type"]
        s = rr["rdata_start"]
        ln = rr["rdlen"]
        raw = buf[s:s + ln]
        try:
            if t == 1 and ln == 4:
                return socket.inet_ntoa(raw)
            if t == 28 and ln == 16:
                return socket.inet_ntop(socket.AF_INET6, raw)
            if t in (2, 5, 12):
                name, _ = _decode_qname(buf, s)
                return name
            if t == 15 and ln >= 3:
                pref = struct.unpack("!H", raw[:2])[0]
                name, _ = _decode_qname(buf, s + 2)
                return f"{pref} {name}"
            if t == 16:
                parts = []
                i = 0
                while i < ln:
                    slen = raw[i]
                    i += 1
                    if i + slen > ln:
                        break
                    parts.append(raw[i:i + slen].decode("utf-8", "replace"))
                    i += slen
                return " ".join(parts)
            if t == 6 and ln >= 22:
                mname, off = _decode_qname(buf, s)
                rname, off = _decode_qname(buf, off)
                if off + 20 > s + ln:
                    return None
                serial, refresh, retry, expire, minimum = struct.unpack(
                    "!IIIII", buf[off:off + 20])
                return f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
            if t == 43 and ln >= 4:
                kt, algo, dt = struct.unpack("!HBB", raw[:4])
                return f"{kt} {algo} {dt} {raw[4:].hex()}"
            if t == 48 and ln >= 4:
                fl, pr, al = struct.unpack("!HBB", raw[:4])
                return f"{fl} {pr} {al} {raw[4:].hex()}"
            if t == 46:
                return raw.hex()[:80] + ("..." if ln > 40 else "")
        except Exception:
            return None
        return raw.hex()

    for group in (answers, authority, additional):
        for rr in group:
            rr["value"] = decode_value(rr)
            rr["type_name"] = DNS_TYPE_NAMES.get(rr["type"], str(rr["type"]))
    return {"id": tid, "rcode": rcode, "rcode_name": DNS_RCODES.get(rcode, "UNKNOWN"),
            "aa": aa, "tc": tc, "questions": questions,
            "answers": answers, "authority": authority, "additional": additional}


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _dns_udp(ns, packet, tid, timeout):
    family = socket.AF_INET6 if ":" in ns else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(packet, (ns, 53))
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DNSError("udp timeout")
            sock.settimeout(remaining)
            try:
                buf, _ = sock.recvfrom(65535)
            except socket.timeout:
                raise DNSError("udp timeout")
            if len(buf) >= 2 and struct.unpack("!H", buf[:2])[0] == tid:
                return buf
    finally:
        sock.close()


def _dns_tcp(ns, packet, timeout):
    family = socket.AF_INET6 if ":" in ns else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((ns, 53))
        sock.sendall(struct.pack("!H", len(packet)) + packet)
        hdr = _recv_exact(sock, 2)
        if len(hdr) < 2:
            raise DNSError("tcp short header")
        ln = struct.unpack("!H", hdr)[0]
        buf = _recv_exact(sock, ln)
        if not buf:
            raise DNSError("tcp empty")
        return buf
    finally:
        sock.close()


def _system_nameservers():
    nameservers = []
    for path in ("/etc/resolv.conf", "/system/etc/resolv.conf"):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            addr = parts[1].split("%")[0]
                            if validate_ip(addr):
                                nameservers.append(addr)
        except OSError:
            continue
    return nameservers


def dns_resolve(qname, qtype="A", server=None, timeout=DNS_TIMEOUT,
                edns_do=False, use_tcp=False):
    if isinstance(qtype, str):
        upper = qtype.upper()
        if upper not in DNS_TYPE_CODES:
            raise DNSError(f"unsupported type: {qtype}")
        qtype_num = DNS_TYPE_CODES[upper]
    else:
        qtype_num = int(qtype)

    candidates = [server] if server else _system_nameservers() or ["1.1.1.1", "8.8.8.8"]
    last_error = None
    for ns in candidates:
        try:
            started = time.monotonic()
            tid, packet = _dns_build_query(qname, qtype_num, edns_do)
            if use_tcp:
                buf = _dns_tcp(ns, packet, timeout)
            else:
                buf = _dns_udp(ns, packet, tid, timeout)
                parsed = _dns_parse(buf, tid)
                if parsed["tc"]:
                    buf = _dns_tcp(ns, packet, timeout)
            parsed = _dns_parse(buf, tid)
            parsed["server"] = ns
            parsed["elapsed_ms"] = (time.monotonic() - started) * 1000
            return parsed
        except (DNSError, OSError) as exc:
            last_error = exc
    raise DNSError(f"all resolvers failed: {last_error}")


def dns_axfr(ns_ip, domain, timeout=8.0):
    tid, packet = _dns_build_query(domain, DNS_TYPE_CODES["AXFR"])
    family = socket.AF_INET6 if ":" in ns_ip else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((ns_ip, 53))
        sock.sendall(struct.pack("!H", len(packet)) + packet)
        records = []
        soa_seen = 0
        for _ in range(200):
            hdr = _recv_exact(sock, 2)
            if len(hdr) < 2:
                break
            ln = struct.unpack("!H", hdr)[0]
            body = _recv_exact(sock, ln)
            if not body:
                break
            parsed = _dns_parse(body, tid)
            if parsed["rcode"] != 0:
                raise DNSError(f"AXFR refused: {parsed['rcode_name']}")
            for rr in parsed["answers"]:
                records.append(rr)
                if rr["type"] == 6:
                    soa_seen += 1
                    if soa_seen >= 2:
                        return records
        return records
    finally:
        sock.close()


class HTTPError(Exception):
    pass


def http_request(method, url, headers=None, timeout=HTTP_TIMEOUT,
                 allow_redirects=True, max_redirects=5, read_limit=None):
    start = time.monotonic()
    history = []
    current = url
    for _ in range(max_redirects + 1):
        parsed = urlparse(current)
        if parsed.scheme not in ("http", "https"):
            raise HTTPError(f"unsupported scheme: {parsed.scheme}")
        host = parsed.hostname
        if not host:
            raise HTTPError("missing host")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        req_headers = {"User-Agent": f"{TOOL_NAME}/{VERSION}",
                       "Accept": "*/*", "Connection": "close"}
        if headers:
            req_headers.update(headers)
        if parsed.scheme == "https":
            context = ssl.create_default_context()
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        try:
            conn.request(method, path, headers=req_headers)
            resp = conn.getresponse()
        except Exception:
            try: conn.close()
            except Exception: pass
            raise
        raw_headers = resp.getheaders()
        header_map = {}
        for k, v in raw_headers:
            header_map.setdefault(k.lower(), []).append(v)
        body = b""
        truncated = False
        try:
            if read_limit is not None:
                chunk = resp.read(read_limit + 1)
                if len(chunk) > read_limit:
                    body = chunk[:read_limit]
                    truncated = True
                else:
                    body = chunk
            else:
                body = resp.read()
        except Exception:
            truncated = True
        conn.close()
        elapsed_ms = (time.monotonic() - start) * 1000
        if allow_redirects and resp.status in (301, 302, 303, 307, 308):
            location = header_map.get("location", [None])[0]
            if location:
                history.append({"url": current, "status": resp.status, "location": location})
                current = urljoin(current, location)
                continue
        return {"url": current, "status": resp.status, "reason": resp.reason,
                "headers": header_map, "raw_headers": raw_headers,
                "body": body, "body_truncated": truncated,
                "history": history, "elapsed_ms": elapsed_ms}
    raise HTTPError(f"too many redirects (> {max_redirects})")


def http_get_json(url, headers=None, timeout=HTTP_TIMEOUT, read_limit=4 * 1024 * 1024):
    resp = http_request("GET", url, headers=headers, timeout=timeout, read_limit=read_limit)
    try:
        data = json.loads(resp["body"].decode("utf-8", "replace"))
    except json.JSONDecodeError as exc:
        raise HTTPError(f"invalid JSON from {url}") from exc
    return data, resp


def _whois_query(server, query, timeout=WHOIS_TIMEOUT):
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall((query + "\r\n").encode("ascii", "replace"))
        data = b""
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if len(data) > 256 * 1024:
                break
    return data.decode("utf-8", "replace")


def _whois_referral(text):
    for line in text.splitlines():
        low = line.lower()
        if low.startswith(("refer:", "whois:", "registrar whois server:",
                           "referralserver:", "whois server:")):
            value = line.split(":", 1)[1].strip()
            if value and not any(c.isspace() for c in value) and validate_domain(value):
                return value
    return None


def whois_lookup(target):
    kind, value = classify_target(target)
    if kind == "invalid":
        raise ValueError(f"invalid target: {target}")
    chain = []
    server = "whois.iana.org"
    query = value
    for _ in range(4):
        try:
            response = _whois_query(server, query)
        except OSError as exc:
            chain.append({"server": server, "error": str(exc)})
            break
        chain.append({"server": server, "response": response})
        referral = _whois_referral(response)
        if not referral or referral == server:
            break
        server = referral
    return {"target": value, "chain": chain}


def tls_fetch_cert(host, port=443, timeout=TLS_TIMEOUT):
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
            version = tls.version()
            cipher = tls.cipher()
    if not cert:
        raise ssl.SSLError("no certificate returned")
    return {"cert": cert, "version": version, "cipher": cipher}


def port_probe(host, port, timeout=PORT_TIMEOUT):
    try:
        parsed = parse_ip(host)
    except ValueError:
        return "UNRESOLVED"
    family = socket.AF_INET6 if parsed.version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        rc = sock.connect_ex((str(parsed), port))
        if rc == 0:
            return "OPEN"
        if rc in (61, 111, 10061):
            return "CLOSED"
        return "UNREACHABLE"
    except socket.timeout:
        return "TIMEOUT"
    except Exception:
        return "ERROR"
    finally:
        try: sock.close()
        except Exception: pass


def banner_grab(host, port, timeout=2.0):
    parsed = parse_ip(host)
    if not parsed:
        return None
    family = socket.AF_INET6 if parsed.version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if sock.connect_ex((str(parsed), port)) != 0:
            return None
        if port in (80, 8080):
            try:
                sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {parsed}\r\n\r\n".encode())
            except OSError:
                pass
        try:
            data = sock.recv(512)
        except socket.timeout:
            return ""
        return data.decode("utf-8", "replace").strip()
    finally:
        try: sock.close()
        except Exception: pass


def _icmp_checksum(payload):
    if len(payload) % 2:
        payload += b"\x00"
    total = 0
    for i in range(0, len(payload), 2):
        total += (payload[i] << 8) + payload[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _icmp_echo(ident, seq, payload=b"IP-FINDER"):
    hdr = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, ident, seq)
    cs = _icmp_checksum(hdr + payload)
    return struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, cs, ident, seq) + payload


def _icmp_parse(raw, expect_id, expect_seq, has_ip_header):
    offset = 0
    if has_ip_header:
        if len(raw) < 20:
            return None
        ihl = (raw[0] & 0x0F) * 4
        if ihl < 20 or ihl > len(raw):
            return None
        offset = ihl
    if len(raw) - offset < 8:
        return None
    try:
        itype, _code, _cs, ident, seq = struct.unpack("!BBHHH", raw[offset:offset + 8])
    except struct.error:
        return None
    if itype == ICMP_ECHO_REPLY and ident == expect_id and seq == expect_seq:
        return "reply"
    if itype in (ICMP_TIME_EXCEEDED, ICMP_DEST_UNREACH):
        inner = offset + 8
        if len(raw) - inner < 20:
            return None
        inner_ihl = (raw[inner] & 0x0F) * 4
        if inner_ihl < 20 or len(raw) - inner < inner_ihl + 8:
            return None
        icmp_off = inner + inner_ihl
        try:
            _t, _c, _cs, iid, iseq = struct.unpack("!BBHHH", raw[icmp_off:icmp_off + 8])
        except struct.error:
            return None
        if iid != expect_id or iseq != expect_seq:
            return None
        return "hop" if itype == ICMP_TIME_EXCEEDED else "unreachable"
    return None


def _traceroute_icmp(target_ip, max_hops, probes, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except OSError:
        return None
    sock.settimeout(timeout)
    ident = os.getpid() & 0xFFFF
    has_ip_header = os.name != "nt"
    hops = []
    reached = False
    try:
        for ttl in range(1, max_hops + 1):
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            samples = []
            responders = set()
            for probe in range(probes):
                seq = (ttl << 8) + probe
                packet = _icmp_echo(ident, seq)
                started = time.perf_counter()
                try:
                    sock.sendto(packet, (target_ip, 0))
                except OSError:
                    samples.append(None)
                    continue
                got = None
                deadline = time.perf_counter() + timeout
                while time.perf_counter() < deadline:
                    try:
                        raw, addr = sock.recvfrom(2048)
                    except (socket.timeout, OSError):
                        break
                    kind = _icmp_parse(raw, ident, seq, has_ip_header)
                    if kind is None:
                        continue
                    elapsed = (time.perf_counter() - started) * 1000
                    got = (addr[0], elapsed, kind)
                    responders.add(addr[0])
                    if kind == "reply":
                        reached = True
                    break
                samples.append(got)
            hops.append({"ttl": ttl, "responders": responders, "samples": samples})
            if reached:
                break
    finally:
        try: sock.close()
        except OSError: pass
    return hops


def _traceroute_tcp(target_ip, port, max_hops, probes, timeout):
    if not sys.platform.startswith("linux"):
        return None
    try:
        test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test.setsockopt(socket.IPPROTO_IP, IP_RECVERR_LINUX, 1)
        test.close()
    except OSError:
        return None
    hops = []
    reached = False
    for ttl in range(1, max_hops + 1):
        samples = []
        responders = set()
        for _probe in range(probes):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            sock.setsockopt(socket.IPPROTO_IP, IP_RECVERR_LINUX, 1)
            sock.settimeout(timeout)
            started = time.perf_counter()
            outcome = None
            try:
                sock.connect((target_ip, port))
                elapsed = (time.perf_counter() - started) * 1000
                outcome = (target_ip, elapsed, "reply")
                responders.add(target_ip)
                reached = True
            except OSError as exc:
                elapsed = (time.perf_counter() - started) * 1000
                responder = None
                reason = "unreachable"
                try:
                    _data, anc, _f, addr = sock.recvmsg(1024, 1024, MSG_ERRQUEUE_LINUX)
                except OSError:
                    anc, addr = [], None
                for level, ctype, cdata in anc:
                    if (level == socket.IPPROTO_IP and ctype == IP_RECVERR_LINUX
                            and len(cdata) >= 16):
                        try:
                            (ee_errno, ee_origin, ee_type, ee_code,
                             _pad, _info, _data) = struct.unpack("IbbbbII", cdata[:16])
                        except struct.error:
                            continue
                        if ee_origin == SO_EE_ORIGIN_ICMP:
                            if ee_type == ICMP_TIME_EXCEEDED:
                                reason = "hop"
                            elif ee_type == ICMP_DEST_UNREACH:
                                reason = "unreachable"
                        if len(cdata) >= 32:
                            try:
                                fam, _p, addr_bytes, _pad = struct.unpack(
                                    "<HH4s8s", cdata[16:32])
                                if fam == socket.AF_INET:
                                    responder = socket.inet_ntoa(addr_bytes)
                            except struct.error:
                                pass
                if responder is None and addr:
                    cand = addr[0]
                    if cand and cand != "0.0.0.0":
                        responder = cand
                if responder is None:
                    outcome = (None, elapsed, type(exc).__name__)
                else:
                    outcome = (responder, elapsed, reason)
                    responders.add(responder)
            finally:
                try: sock.close()
                except OSError: pass
            samples.append(outcome)
        hops.append({"ttl": ttl, "responders": responders, "samples": samples})
        if reached:
            break
    return hops


_ENRICH_CACHE = {}


def _hop_enrichment(ip):
    if ip in _ENRICH_CACHE:
        return _ENRICH_CACHE[ip]
    try:
        ptr = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        ptr = None
    asn = None
    try:
        with socket.create_connection(("whois.cymru.com", 43), timeout=4) as cs:
            cs.sendall(f" -v {ip}\r\n".encode())
            cs.settimeout(4)
            data = b""
            while True:
                try:
                    chunk = cs.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
                if len(data) > 8192:
                    break
        for ln in data.decode("utf-8", "replace").splitlines():
            ln = ln.strip()
            if not ln or ln.lower().startswith("as "):
                continue
            parts = [p.strip() for p in ln.split("|")]
            if len(parts) >= 7 and parts[0].isdigit():
                asn = f"AS{parts[0]} {parts[6]}"
                break
    except OSError:
        asn = None
    _ENRICH_CACHE[ip] = (ptr, asn)
    return ptr, asn


def _traceroute_capability():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.close()
        return "ICMP raw (elevated)"
    except OSError:
        pass
    if sys.platform.startswith("linux"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_IP, IP_RECVERR_LINUX, 1)
            s.close()
            return "TCP-SYN (IP_RECVERR, unprivileged)"
        except OSError:
            pass
    return "unavailable"


def tool_01_public_ip(results):
    try:
        resp = http_request("GET", "https://api.ipify.org", read_limit=200)
        ip = resp["body"].decode("ascii", "replace").strip()
        if not validate_ip(ip):
            return emit("Public IP", [("Result", f"invalid response: {ip[:60]}"),
                                      ("Source", "api.ipify.org")], results)
        return emit("Public IP", [("Public IP", ip), ("Source", "api.ipify.org")], results)
    except Exception as exc:
        return emit("Public IP", [("Error", f"{type(exc).__name__}: {exc}")], results)


def tool_02_reverse_dns(ip, results):
    parsed = parse_ip(ip)
    if not parsed:
        return emit("Reverse DNS", [("Error", f"invalid IP: {ip}")], results)
    query = parsed.reverse_pointer
    try:
        resp = dns_resolve(query, "PTR")
    except DNSError as exc:
        return emit("Reverse DNS", [("Error", str(exc))], results)
    ptrs = [rr["value"] for rr in resp["answers"] if rr["type"] == 12]
    if not ptrs:
        return emit("Reverse DNS", [("Result", "no PTR record"),
                                    ("Status", resp["rcode_name"])], results)
    rows = [("PTR", p) for p in ptrs] + [("Query", query), ("Server", resp["server"])]
    return emit(f"Reverse DNS - {parsed}", rows, results)


def tool_03_domain_to_ip(domain, results):
    if not validate_domain(domain):
        return emit("Domain to IP", [("Error", f"invalid domain: {domain}")], results)
    rows = []
    for rtype in ("A", "AAAA"):
        try:
            resp = dns_resolve(domain, rtype)
            addrs = [rr["value"] for rr in resp["answers"] if rr["type"] == DNS_TYPE_CODES[rtype]]
            if addrs:
                rows.extend((rtype, a) for a in addrs)
            else:
                rows.append((rtype, f"none ({resp['rcode_name']})"))
        except DNSError as exc:
            rows.append((rtype, f"error: {exc}"))
    return emit(f"Domain to IP - {domain}", rows, results)


def tool_04_dns_records(domain, results):
    if not validate_domain(domain):
        return emit("DNS Records", [("Error", f"invalid domain: {domain}")], results)
    rows = []
    for rtype in DNS_RECORD_TYPES:
        try:
            resp = dns_resolve(domain, rtype)
        except DNSError as exc:
            rows.append((rtype, f"error: {exc}"))
            continue
        if resp["rcode"] == 3:
            rows.append((rtype, "NXDOMAIN"))
            break
        matches = [rr for rr in resp["answers"]
                   if rr["type"] == DNS_TYPE_CODES[rtype]]
        if matches:
            for rr in matches:
                rows.append((rtype, f"{rr['value']}  (TTL {rr['ttl']})"))
        else:
            rows.append((rtype, f"none ({resp['rcode_name']})"))
    return emit(f"DNS Records - {domain}", rows, results)


def tool_05_geoip(ip, results):
    parsed = parse_ip(ip)
    if not parsed:
        return emit("GeoIP", [("Error", f"invalid IP: {ip}")], results)
    try:
        data, _ = http_get_json(f"https://ipwho.is/{parsed}")
    except Exception as exc:
        return emit("GeoIP", [("Error", f"{type(exc).__name__}: {exc}")], results)
    if not data.get("success"):
        return emit("GeoIP", [("Error", data.get("message", "unknown"))], results)
    conn = data.get("connection") or {}
    rows = [
        ("IP", data.get("ip", str(parsed))),
        ("Type", data.get("type", "?")),
        ("Country", data.get("country", "?")),
        ("Region", data.get("region", "?")),
        ("City", data.get("city", "?")),
        ("ISP", conn.get("isp", "?")),
        ("Organization", conn.get("org", "?")),
        ("ASN", conn.get("asn", "?")),
        ("Timezone", (data.get("timezone") or {}).get("id", "?")),
        ("Source", "ipwho.is (HTTPS)"),
    ]
    return emit(f"GeoIP - {parsed}", rows, results)


def tool_06_whois(target, results):
    kind, value = classify_target(target)
    if kind == "invalid":
        return emit("WHOIS", [("Error", f"invalid target: {target}")], results)
    try:
        result = whois_lookup(value)
    except Exception as exc:
        return emit("WHOIS", [("Error", f"{type(exc).__name__}: {exc}")], results)
    rows = [("Target", value)]
    for hop in result["chain"]:
        if "error" in hop:
            rows.append((f"{hop['server']}!", hop["error"]))
            continue
        rows.append((hop["server"], f"{len(hop['response'])} chars"))
        interesting = []
        for line in hop["response"].splitlines():
            ll = line.lower()
            if any(ll.startswith(k) for k in (
                    "domain name:", "registrar:", "creation date:", "expiry date:",
                    "updated date:", "name server:", "netname:", "org-name:",
                    "country:", "descr:", "inetnum:", "inet6num:", "regdate:")):
                interesting.append(line.strip())
        rows.extend(("", x) for x in interesting[:10])
    return emit(f"WHOIS - {value}", rows, results)


def tool_07_port_scan(ip, results):
    parsed = parse_ip(ip)
    if not parsed:
        return emit("Port Scan", [("Error", f"invalid IP: {ip}")], results)
    rows = []
    info(f"probing {len(COMMON_PORTS)} ports on {parsed}")
    for port, service in COMMON_PORTS.items():
        state = port_probe(str(parsed), port)
        rows.append((f"{port}/{service}", state))
    return emit(f"Port Scan - {parsed}", rows, results)


def tool_08_http_headers(target, results):
    url = normalize_url(target)
    if not url:
        return emit("HTTP Headers", [("Error", f"invalid URL: {target}")], results)
    try:
        resp = http_request("GET", url, read_limit=1024)
    except Exception as exc:
        return emit("HTTP Headers", [("Error", f"{type(exc).__name__}: {exc}")], results)
    rows = [("Status", f"{resp['status']} {resp['reason']}"),
            ("Final URL", resp["url"]),
            ("Elapsed", f"{resp['elapsed_ms']:.1f} ms")]
    for k, vals in resp["headers"].items():
        for v in vals:
            rows.append((k, v))
    return emit(f"HTTP Headers - {url}", rows, results)


def tool_09_tls_cert(target, results):
    kind, value = classify_target(target)
    if kind == "invalid":
        return emit("TLS Certificate", [("Error", f"invalid target: {target}")], results)
    host = value
    if kind == "ip":
        return emit("TLS Certificate",
                    [("Error", "certificate inspection requires a hostname (SNI)")], results)
    try:
        info(f"TLS handshake with {host}:443")
        cert_info = tls_fetch_cert(host)
    except Exception as exc:
        return emit("TLS Certificate", [("Error", f"{type(exc).__name__}: {exc}")], results)
    cert = cert_info["cert"]
    subject = dict(item[0] for item in cert.get("subject", ()))
    issuer = dict(item[0] for item in cert.get("issuer", ()))
    san = cert.get("subjectAltName", ())
    rows = [
        ("Subject CN", subject.get("commonName", "?")),
        ("Issuer", issuer.get("organizationName", issuer.get("commonName", "?"))),
        ("notBefore", cert.get("notBefore", "?")),
        ("notAfter", cert.get("notAfter", "?")),
        ("Protocol", cert_info["version"] or "?"),
        ("Cipher", cert_info["cipher"][0] if cert_info["cipher"] else "?"),
    ]
    dns_sans = [v for t, v in san if t == "DNS"]
    if dns_sans:
        rows.append(("SANs", f"{len(dns_sans)} DNS names"))
        rows.extend(("", s) for s in dns_sans[:10])
    return emit(f"TLS Certificate - {host}", rows, results)


def tool_10_subdomains(domain, results):
    if not validate_domain(domain):
        return emit("Subdomains", [("Error", f"invalid domain: {domain}")], results)
    rows = []
    found = 0
    for sub in COMMON_SUBDOMAINS:
        fqdn = f"{sub}.{domain}"
        try:
            resp = dns_resolve(fqdn, "A")
            addrs = [rr["value"] for rr in resp["answers"] if rr["type"] == 1]
        except DNSError:
            continue
        if addrs:
            rows.append((fqdn, ", ".join(addrs)))
            found += 1
    if not found:
        rows.append(("Result", "no common subdomains found"))
    return emit(f"Subdomains - {domain}", rows, results)


def tool_11_asn(target, results):
    kind, value = classify_target(target)
    if kind == "invalid":
        return emit("ASN / ISP", [("Error", f"invalid target: {target}")], results)
    if kind == "domain":
        try:
            resp = dns_resolve(value, "A")
            addrs = [rr["value"] for rr in resp["answers"] if rr["type"] == 1]
            if not addrs:
                return emit("ASN / ISP", [("Error", f"{value} did not resolve")], results)
            value = addrs[0]
        except DNSError as exc:
            return emit("ASN / ISP", [("Error", str(exc))], results)
    try:
        data, _ = http_get_json(f"https://ipwho.is/{value}")
    except Exception as exc:
        return emit("ASN / ISP", [("Error", f"{type(exc).__name__}: {exc}")], results)
    if not data.get("success"):
        return emit("ASN / ISP", [("Error", data.get("message", "unknown"))], results)
    conn = data.get("connection") or {}
    asn = conn.get("asn", "?")
    rows = [
        ("IP", data.get("ip", value)),
        ("ISP", conn.get("isp", "?")),
        ("Organization", conn.get("org", "?")),
        ("ASN", f"AS{asn}" if asn != "?" and not str(asn).upper().startswith("AS") else asn),
        ("Source", "ipwho.is (HTTPS)"),
    ]
    return emit(f"ASN / ISP - {value}", rows, results)


def tool_12_rdap(target, results):
    kind, value = classify_target(target)
    if kind == "invalid":
        return emit("RDAP", [("Error", f"invalid target: {target}")], results)
    url = f"https://rdap.org/ip/{value}" if kind == "ip" else f"https://rdap.org/domain/{value}"
    try:
        data, _ = http_get_json(url, headers={"Accept": "application/rdap+json"})
    except Exception as exc:
        return emit("RDAP", [("Error", f"{type(exc).__name__}: {exc}")], results)
    rows = [("Target", value)]
    for field in ("name", "handle", "type", "country"):
        if data.get(field):
            rows.append((field.capitalize(), data[field]))
    for entity in data.get("entities", []) or []:
        roles = ", ".join(entity.get("roles", []))
        for entry in (entity.get("vcardArray") or [None, []])[1]:
            if entry and entry[0] == "fn":
                rows.append(("Entity", f"{entry[3]} ({roles})"))
                break
    for ev in data.get("events", []) or []:
        action = ev.get("eventAction", "")
        if action in ("registration", "expiration", "last changed"):
            rows.append((action.capitalize(), ev.get("eventDate", "?")))
    statuses = data.get("status") or []
    if statuses:
        rows.append(("Status", ", ".join(statuses)))
    ns_list = [ns.get("ldhName", "?") for ns in (data.get("nameservers") or [])]
    if ns_list:
        rows.append(("Nameservers", ", ".join(ns_list)))
    return emit(f"RDAP - {value}", rows, results)


def tool_13_propagation(domain, rtype, results):
    if not validate_domain(domain):
        return emit("DNS Propagation", [("Error", f"invalid domain: {domain}")], results)
    rtype = (rtype or "A").upper()
    if rtype not in DNS_RECORD_TYPES:
        return emit("DNS Propagation", [("Error", f"unsupported type: {rtype}")], results)
    rows = []
    results_by_server = {}
    for label, server in PUBLIC_RESOLVERS:
        try:
            resp = dns_resolve(domain, rtype, server=server)
            vals = sorted(rr["value"] for rr in resp["answers"]
                          if rr["type"] == DNS_TYPE_CODES[rtype])
            results_by_server[label] = vals
            rows.append((f"{label} ({server})", ", ".join(vals) if vals else f"none ({resp['rcode_name']})"))
        except DNSError as exc:
            results_by_server[label] = None
            rows.append((f"{label} ({server})", f"error: {exc}"))
    usable = [tuple(v) for v in results_by_server.values() if v is not None]
    if len(usable) >= 2:
        if len(set(usable)) == 1:
            rows.append(("Verdict", "all responders agree"))
        else:
            rows.append(("Verdict", "ANSWERS DIFFER between resolvers"))
    else:
        rows.append(("Verdict", "insufficient responses"))
    return emit(f"DNS Propagation - {domain} {rtype}", rows, results)


def tool_14_dnssec(domain, results):
    if not validate_domain(domain):
        return emit("DNSSEC", [("Error", f"invalid domain: {domain}")], results)
    rows = []
    states = {}
    for rtype in ("DS", "DNSKEY", "RRSIG"):
        try:
            resp = dns_resolve(domain, rtype, edns_do=True)
            matched = [rr for rr in resp["answers"] if rr["type"] == DNS_TYPE_CODES[rtype]]
            states[rtype] = matched
            rows.append((rtype, f"{len(matched)} record(s)" if matched else "none"))
        except DNSError as exc:
            states[rtype] = []
            rows.append((rtype, f"error: {exc}"))
    ds = states.get("DS", [])
    dnskey = states.get("DNSKEY", [])
    if not ds and not dnskey:
        rows.append(("Status", "DNSSEC not configured"))
    elif ds and dnskey:
        rows.append(("Status", "records present (NOT validated)"))
        rows.append(("Validate", "requires a validating resolver — this tool does not chain-validate"))
    else:
        rows.append(("Status", "partial / inconsistent DNSSEC data"))
    return emit(f"DNSSEC - {domain}", rows, results)


def tool_15_subnet(cidr, results):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except (ValueError, TypeError):
        return emit("Subnet Calculator", [("Error", f"invalid CIDR: {cidr}")], results)
    rows = [
        ("Version", f"IPv{net.version}"),
        ("Network", str(net.network_address)),
        ("Prefix", f"/{net.prefixlen}"),
        ("Total addresses", str(net.num_addresses)),
    ]
    if net.version == 4:
        rows.append(("Netmask", str(net.netmask)))
        rows.append(("Wildcard", str(net.hostmask)))
        rows.append(("Broadcast", str(net.broadcast_address)))
        if net.prefixlen <= 30:
            rows.append(("First usable", str(net.network_address + 1)))
            rows.append(("Last usable", str(net.broadcast_address - 1)))
            rows.append(("Usable hosts", str(net.num_addresses - 2)))
        elif net.prefixlen == 31:
            rows.append(("Note", "/31 point-to-point (RFC 3021)"))
        else:
            rows.append(("Note", "/32 single host"))
    else:
        if net.prefixlen <= 127:
            rows.append(("First address", str(net.network_address + 1)))
            rows.append(("Last address", str(net.broadcast_address - 1)))
    return emit(f"Subnet - {net}", rows, results)


def tool_16_ip_reputation(ip, results):
    parsed = parse_ip(ip)
    if not parsed or not parsed.is_global:
        return emit("IP Reputation", [("Error", "requires a public IP")], results)
    try:
        data, _ = http_get_json(
            f"https://ipaddress.to/api/score/{parsed}",
            headers={"Accept": "application/json"})
    except Exception as exc:
        return emit("IP Reputation", [("Error", f"{type(exc).__name__}: {exc}")], results)
    if not data.get("success"):
        return emit("IP Reputation", [("Error", data.get("error", "service error"))], results)
    checks = data.get("checks") or {}
    rows = [
        ("IP", data.get("ip", str(parsed))),
        ("Score", f"{data.get('score', '?')}/100"),
        ("Risk", str(data.get("risk", "?")).upper()),
        ("VPN", checks.get("vpn_detected", "?")),
        ("Proxy", checks.get("commercial_proxy", "?")),
        ("Tor", checks.get("tor_exit", "?")),
        ("Blocklisted", checks.get("blocklist_listed", "?")),
        ("Source", "ipaddress.to"),
    ]
    return emit(f"IP Reputation - {parsed}", rows, results)


def _dns_txt(name):
    resp = dns_resolve(name, "TXT")
    return [rr["value"] for rr in resp["answers"] if rr["type"] == 16]


def tool_17_email_security(domain, dkim_selector, results):
    if not validate_domain(domain):
        return emit("Email Security", [("Error", f"invalid domain: {domain}")], results)
    rows = []
    try:
        mx_resp = dns_resolve(domain, "MX")
        mx = [rr["value"] for rr in mx_resp["answers"] if rr["type"] == 15]
        rows.append(("MX", f"{len(mx)} record(s)"))
        rows.extend(("", m) for m in mx[:5])
    except DNSError as exc:
        rows.append(("MX", f"error: {exc}"))
    try:
        txts = _dns_txt(domain)
        spf = [t for t in txts if t.lower().startswith("v=spf1")]
        rows.append(("SPF", spf[0] if spf else "not found"))
        if len(spf) > 1:
            rows.append(("SPF warning", "multiple SPF records"))
    except DNSError as exc:
        rows.append(("SPF", f"error: {exc}"))
    try:
        dmarc = [t for t in _dns_txt(f"_dmarc.{domain}") if "v=dmarc1" in t.lower()]
        rows.append(("DMARC", dmarc[0] if dmarc else "not found"))
    except DNSError as exc:
        rows.append(("DMARC", f"error: {exc}"))
    if dkim_selector:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,63}", dkim_selector):
            rows.append(("DKIM", "invalid selector"))
        else:
            try:
                recs = _dns_txt(f"{dkim_selector}._domainkey.{domain}")
                rows.append(("DKIM", recs[0] if recs else "not found"))
            except DNSError as exc:
                rows.append(("DKIM", f"error: {exc}"))
    return emit(f"Email Security - {domain}", rows, results)


def tool_18_http_diag(url, results):
    url = normalize_url(url)
    if not url:
        return emit("HTTP Diagnostics", [("Error", f"invalid URL: {url}")], results)
    try:
        resp = http_request("GET", url, read_limit=2048)
    except Exception as exc:
        return emit("HTTP Diagnostics", [("Error", f"{type(exc).__name__}: {exc}")], results)
    rows = [
        ("Status", f"{resp['status']} {resp['reason']}"),
        ("Final URL", resp["url"]),
        ("Elapsed", f"{resp['elapsed_ms']:.1f} ms"),
        ("Redirects", str(len(resp["history"]))),
        ("Content-Type", resp["headers"].get("content-type", ["?"])[0]),
    ]
    for h in resp["history"]:
        rows.append((f"{h['status']}", f"{h['url']} -> {h['location']}"))
    for key in ("server", "strict-transport-security", "content-security-policy"):
        if key in resp["headers"]:
            rows.append((key, resp["headers"][key][0]))
    return emit(f"HTTP Diagnostics - {url}", rows, results)


def tool_19_local_network(results):
    rows = [("Hostname", socket.gethostname())]
    addrs = set()
    try:
        for item in socket.getaddrinfo(socket.gethostname(), None):
            addr = item[4][0].split("%")[0]
            if addr and not addr.startswith("127.") and addr != "::1":
                addrs.add(addr)
    except OSError:
        pass
    rows.append(("Local addresses", ", ".join(sorted(addrs)) if addrs else "unavailable"))
    rows.append(("Gateway", "not detected (portable stdlib method not available)"))
    return emit("Local Network", rows, results)


def tool_20_ttl(domain, rtype, results):
    if not validate_domain(domain):
        return emit("DNS TTL", [("Error", f"invalid domain: {domain}")], results)
    rtype = (rtype or "A").upper()
    if rtype not in DNS_RECORD_TYPES:
        return emit("DNS TTL", [("Error", f"unsupported type: {rtype}")], results)
    try:
        resp = dns_resolve(domain, rtype)
    except DNSError as exc:
        return emit("DNS TTL", [("Error", str(exc))], results)
    rows = [("Status", resp["rcode_name"]), ("Query time", f"{resp['elapsed_ms']:.1f} ms")]
    matches = [rr for rr in resp["answers"] if rr["type"] == DNS_TYPE_CODES[rtype]]
    for rr in matches:
        rows.append((f"TTL {rr['ttl']}s", rr["value"]))
    if not matches:
        rows.append(("Result", f"no {rtype} records"))
    return emit(f"DNS TTL - {domain} {rtype}", rows, results)


def tool_21_cdn_waf(url, results):
    url = normalize_url(url)
    if not url:
        return emit("CDN / WAF", [("Error", f"invalid URL: {url}")], results)
    try:
        resp = http_request("GET", url, allow_redirects=False, read_limit=1024)
    except Exception as exc:
        return emit("CDN / WAF", [("Error", f"{type(exc).__name__}: {exc}")], results)
    hdrs = " ".join(f"{k}: {v[0]}" for k, v in resp["headers"].items()).lower()
    vendors = {
        "Cloudflare": ("cf-ray", "cf-cache-status"),
        "Akamai": ("akamai", "x-akamai-transformed"),
        "Fastly": ("fastly", "x-served-by"),
        "CloudFront": ("cloudfront", "x-amz-cf-id"),
        "Imperva/Incapsula": ("incap_ses", "x-iinfo"),
        "Sucuri": ("x-sucuri-id", "x-sucuri-cache"),
    }
    rows = [("Status", str(resp["status"]))]
    hits = 0
    for vendor, tokens in vendors.items():
        if any(t in hdrs for t in tokens):
            rows.append(("Detected", vendor))
            hits += 1
    if hits == 0:
        rows.append(("Detected", "no known CDN/WAF header fingerprint"))
    return emit(f"CDN / WAF - {url}", rows, results)


def tool_22_redirects(url, results):
    url = normalize_url(url)
    if not url:
        return emit("Redirects", [("Error", f"invalid URL: {url}")], results)
    try:
        resp = http_request("GET", url, read_limit=512)
    except Exception as exc:
        return emit("Redirects", [("Error", f"{type(exc).__name__}: {exc}")], results)
    rows = []
    for i, hop in enumerate(resp["history"], 1):
        rows.append((f"Hop {i}", f"{hop['status']} -> {hop['location']}"))
    rows.append(("Final", f"{resp['status']} {resp['url']}"))
    rows.append(("Redirect count", str(len(resp["history"]))))
    return emit(f"Redirects - {url}", rows, results)


def tool_23_http_perf(url, results):
    url = normalize_url(url)
    if not url:
        return emit("HTTP Performance", [("Error", f"invalid URL: {url}")], results)
    try:
        resp = http_request("GET", url, read_limit=1024 * 1024)
    except Exception as exc:
        return emit("HTTP Performance", [("Error", f"{type(exc).__name__}: {exc}")], results)
    rows = [
        ("Status", str(resp["status"])),
        ("Elapsed", f"{resp['elapsed_ms']:.1f} ms"),
        ("Redirects", str(len(resp["history"]))),
        ("Bytes read", str(len(resp["body"]))),
        ("Truncated", str(resp["body_truncated"])),
        ("Note", "body sample capped at 1 MiB"),
    ]
    return emit(f"HTTP Performance - {url}", rows, results)


def tool_24_ct(domain, results):
    if not validate_domain(domain):
        return emit("Certificate Transparency", [("Error", f"invalid domain: {domain}")], results)
    try:
        resp = http_request(
            "GET",
            f"https://crt.sh/?q=%25.{domain}&output=json",
            read_limit=4 * 1024 * 1024,
            timeout=20.0,
        )
    except Exception as exc:
        return emit("Certificate Transparency",
                    [("Error", f"{type(exc).__name__}: {exc}"),
                     ("Note", "crt.sh may be slow or unreachable — retry later")], results)
    try:
        records = json.loads(resp["body"].decode("utf-8", "replace"))
    except json.JSONDecodeError:
        return emit("Certificate Transparency", [("Error", "crt.sh returned non-JSON")], results)
    names = set()
    for item in records if isinstance(records, list) else []:
        name_field = str(item.get("name_value", "")).strip()
        for value in name_field.splitlines():
            v = value.strip().lower()
            if v:
                names.add(v)
    rows = [("Unique names", str(len(names)))]
    rows.extend(("", n) for n in sorted(names)[:80])
    if len(names) > 80:
        rows.append(("", f"...{len(names) - 80} more"))
    return emit(f"Certificate Transparency - {domain}", rows, results)


def tool_25_security_headers(url, results):
    url = normalize_url(url)
    if not url:
        return emit("Security Headers", [("Error", f"invalid URL: {url}")], results)
    try:
        resp = http_request("GET", url, read_limit=512)
    except Exception as exc:
        return emit("Security Headers", [("Error", f"{type(exc).__name__}: {exc}")], results)
    checks = ["strict-transport-security", "content-security-policy",
              "x-content-type-options", "x-frame-options",
              "referrer-policy", "permissions-policy"]
    rows = [("Status", str(resp["status"]))]
    for h in checks:
        vals = resp["headers"].get(h)
        rows.append((h, vals[0] if vals else "MISSING"))
    return emit(f"Security Headers - {url}", rows, results)


def tool_26_latency(target, results):
    kind, value = classify_target(target)
    if kind == "invalid":
        return emit("Latency", [("Error", f"invalid target: {target}")], results)
    try:
        address = socket.gethostbyname(value)
    except socket.gaierror:
        return emit("Latency", [("Error", f"could not resolve {value}")], results)
    rows = [("Host", value), ("Resolved", address)]
    samples = []
    for i in range(4):
        started = time.perf_counter()
        try:
            with socket.create_connection((address, 443), timeout=2):
                samples.append((time.perf_counter() - started) * 1000)
        except OSError:
            pass
        time.sleep(0.1)
    if samples:
        rows.append(("Successful", f"{len(samples)}/4"))
        rows.append(("Min", f"{min(samples):.1f} ms"))
        rows.append(("Avg", f"{sum(samples)/len(samples):.1f} ms"))
        rows.append(("Max", f"{max(samples):.1f} ms"))
    else:
        rows.append(("Result", "no successful TCP/443 connects"))
    rows.append(("Note", "TCP/443 connect — not ICMP ping"))
    return emit(f"Latency - {value}", rows, results)


def tool_27_dns_health(domain, results):
    if not validate_domain(domain):
        return emit("DNS Health", [("Error", f"invalid domain: {domain}")], results)
    rows = []
    for rtype in ("A", "AAAA", "MX", "NS", "SOA", "TXT"):
        try:
            resp = dns_resolve(domain, rtype)
            matches = [rr for rr in resp["answers"] if rr["type"] == DNS_TYPE_CODES[rtype]]
            if matches:
                ttl = matches[0]["ttl"]
                values = "; ".join(rr["value"] for rr in matches[:5])
                rows.append((rtype, f"OK ({resp['elapsed_ms']:.1f}ms TTL {ttl}) {values}"))
            else:
                rows.append((rtype, resp["rcode_name"]))
        except DNSError as exc:
            rows.append((rtype, f"error: {exc}"))
    return emit(f"DNS Health - {domain}", rows, results)


def tool_28_smart(target, results):
    kind, value = classify_target(target)
    if kind == "invalid":
        return emit("Smart Diagnostic", [("Error", f"invalid target: {target}")], results)
    rows = [("Target", value)]
    if kind == "domain":
        try:
            resp = dns_resolve(value, "A")
            addrs = [rr["value"] for rr in resp["answers"] if rr["type"] == 1]
            rows.append(("DNS A", ", ".join(addrs) if addrs else resp["rcode_name"]))
        except DNSError as exc:
            rows.append(("DNS A", f"error: {exc}"))
    if kind in ("domain", "ip"):
        for scheme in ("https", "http"):
            try:
                resp = http_request("GET", f"{scheme}://{value}", read_limit=512)
                rows.append((f"{scheme.upper()}", f"{resp['status']} {resp['reason']} in {resp['elapsed_ms']:.0f}ms"))
                break
            except Exception as exc:
                rows.append((f"{scheme.upper()}", f"error: {type(exc).__name__}"))
    rows.append(("Note", "triage summary only"))
    return emit(f"Smart Diagnostic - {value}", rows, results)


def tool_29_dns_compare(domain, rtype, results):
    if not validate_domain(domain):
        return emit("DNS Compare", [("Error", f"invalid domain: {domain}")], results)
    rtype = (rtype or "A").upper()
    if rtype not in DNS_RECORD_TYPES:
        return emit("DNS Compare", [("Error", f"unsupported type: {rtype}")], results)
    rows = []
    sets = {}
    for label, server in PUBLIC_RESOLVERS:
        try:
            resp = dns_resolve(domain, rtype, server=server)
            vals = sorted(rr["value"] for rr in resp["answers"]
                          if rr["type"] == DNS_TYPE_CODES[rtype])
            sets[label] = tuple(vals)
            rows.append((label, ", ".join(vals) if vals else "(none)"))
        except DNSError as exc:
            sets[label] = None
            rows.append((label, f"error: {exc}"))
    usable = [v for v in sets.values() if v is not None]
    if len(usable) >= 2:
        rows.append(("Verdict", "agree" if len(set(usable)) == 1 else "differ"))
    else:
        rows.append(("Verdict", "insufficient responses"))
    return emit(f"DNS Compare - {domain} {rtype}", rows, results)


def tool_30_traceroute(target, results):
    host = (target or "").strip()
    if host.startswith(("http://", "https://")):
        try:
            host = urlparse(host).hostname or ""
        except ValueError:
            return emit("Traceroute", [("Error", "invalid target URL")], results)
    try:
        target_ip = socket.gethostbyname(host)
    except socket.gaierror:
        return emit("Traceroute", [("Error", f"could not resolve {host}")], results)
    info(f"tracing {host} ({target_ip})")
    hops = _traceroute_icmp(target_ip, 15, 3, 1.5)
    method = "ICMP Echo (raw)"
    if hops is None:
        hops = _traceroute_tcp(target_ip, 443, 15, 3, 1.5)
        method = "TCP SYN/443 (IP_RECVERR)"
    if hops is None:
        return emit("Traceroute", [("Error", "no raw-ICMP or IP_RECVERR path available"),
                                   ("Platform", sys.platform)], results)
    rows = [("Target", f"{host} ({target_ip})"), ("Method", method)]
    reached = False
    for hop in hops:
        times = [s[1] for s in hop["samples"] if s and s[0] and s[1] is not None]
        loss = sum(1 for s in hop["samples"] if not s or not s[0]) / len(hop["samples"]) * 100
        primary = sorted(hop["responders"])[0] if hop["responders"] else "*"
        rtt = f"{min(times):.1f}/{sum(times)/len(times):.1f}/{max(times):.1f} ms" if times else "*"
        ecmp = f" (+{len(hop['responders']) - 1} more)" if len(hop["responders"]) > 1 else ""
        rows.append((f"Hop {hop['ttl']}", f"{rtt}  loss={loss:.0f}%  {primary}{ecmp}"))
        if primary != "*":
            ptr, asn = _hop_enrichment(primary)
            if ptr:
                rows.append(("", f"    PTR: {ptr}"))
            if asn:
                rows.append(("", f"    ASN: {asn}"))
        if primary == target_ip:
            rows.append(("Result", f"target reached at hop {hop['ttl']}"))
            reached = True
            break
    if not reached:
        rows.append(("Result", "max hops reached"))
    return emit(f"Traceroute - {host}", rows, results)


def tool_31_connection_stability(target, port, samples, interval, results):
    kind, value = classify_target(target)
    if kind == "invalid":
        return emit("Connection Stability", [("Error", f"invalid target: {target}")], results)
    try:
        port = int(port or 443)
        samples = int(samples or 5)
        interval = float(interval or 2)
    except (TypeError, ValueError):
        return emit("Connection Stability", [("Error", "invalid port/samples/interval")], results)
    if not (1 <= port <= 65535 and 1 <= samples <= 30 and 1 <= interval <= 10):
        return emit("Connection Stability",
                    [("Error", "port 1-65535, samples 1-30, interval 1-10s")], results)
    try:
        address = socket.gethostbyname(value)
    except socket.gaierror:
        return emit("Connection Stability", [("Error", f"could not resolve {value}")], results)
    checks = []
    for i in range(samples):
        started = time.perf_counter()
        try:
            with socket.create_connection((address, port), timeout=3):
                checks.append((True, (time.perf_counter() - started) * 1000))
        except OSError:
            checks.append((False, (time.perf_counter() - started) * 1000))
        if i + 1 < samples:
            time.sleep(interval)
    ok_count = sum(1 for c in checks if c[0])
    rows = [
        ("Target", f"{address}:{port}"),
        ("Samples", str(samples)),
        ("Successful", f"{ok_count}/{samples}"),
        ("Rate", f"{ok_count / samples * 100:.1f}%"),
    ]
    good = [c[1] for c in checks if c[0]]
    if good:
        rows.append(("Min/Avg/Max", f"{min(good):.1f} / {sum(good)/len(good):.1f} / {max(good):.1f} ms"))
    return emit(f"Connection Stability - {value}:{port}", rows, results)


def tool_32_tls_compat(target, port, results):
    kind, value = classify_target(target)
    if kind == "invalid":
        return emit("TLS Compatibility", [("Error", f"invalid target: {target}")], results)
    host = value
    try:
        port = int(port or 443)
    except (TypeError, ValueError):
        return emit("TLS Compatibility", [("Error", "invalid port")], results)
    if not 1 <= port <= 65535:
        return emit("TLS Compatibility", [("Error", "port out of range")], results)
    versions = [
        ("TLS 1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
        ("TLS 1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
        ("TLS 1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
        ("TLS 1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
    ]
    rows = [("Target", f"{host}:{port}"), ("OpenSSL", ssl.OPENSSL_VERSION)]
    for label, ver in versions:
        if ver is None:
            rows.append((label, "unavailable in this build"))
            continue
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = ver
            context.maximum_version = ver
            with socket.create_connection((host, port), timeout=3) as raw_sock:
                sname = host if not validate_ip(host) else None
                with context.wrap_socket(raw_sock, server_hostname=sname) as tls:
                    rows.append((label, f"negotiated ({tls.version()})"))
        except (OSError, ssl.SSLError, ValueError) as exc:
            rows.append((label, f"failed ({type(exc).__name__})"))
    rows.append(("Note", "certificate verification disabled for this probe only"))
    return emit(f"TLS Compatibility - {host}:{port}", rows, results)


def tool_33_http_method(url, results):
    url = normalize_url(url)
    if not url:
        return emit("HTTP Method", [("Error", f"invalid URL: {url}")], results)
    try:
        resp = http_request("OPTIONS", url, allow_redirects=False, read_limit=512)
    except Exception as exc:
        return emit("HTTP Method", [("Error", f"{type(exc).__name__}: {exc}")], results)
    rows = [
        ("Status", str(resp["status"])),
        ("Allow", resp["headers"].get("allow", ["(not supplied)"])[0]),
        ("CORS Methods", resp["headers"].get("access-control-allow-methods", ["(not supplied)"])[0]),
    ]
    return emit(f"HTTP Method - {url}", rows, results)


def tool_34_ipv6_readiness(domain, results):
    if not validate_domain(domain):
        return emit("IPv6 Readiness", [("Error", f"invalid domain: {domain}")], results)
    try:
        infos = socket.getaddrinfo(domain, 443, socket.AF_INET6, socket.SOCK_STREAM)
        addrs = list(dict.fromkeys(i[4][0] for i in infos))
    except socket.gaierror:
        return emit("IPv6 Readiness",
                    [("AAAA", "no AAAA record"), ("Status", "IPv6 not resolvable")], results)
    rows = [("AAAA", ", ".join(addrs[:8]))]
    connected = False
    for addr in addrs[:2]:
        try:
            with socket.create_connection((addr, 443, 0, 0), timeout=3):
                rows.append(("TCP/443", f"connected to {addr}"))
                connected = True
                break
        except OSError as exc:
            rows.append(("TCP/443", f"{addr}: {type(exc).__name__}"))
    rows.append(("Status", "reachable" if connected else "AAAA present, connect failed"))
    return emit(f"IPv6 Readiness - {domain}", rows, results)


def _local_data_dir():
    return os.path.join(os.path.expanduser("~"), ".ip-finder")


def _load_json(filename, default):
    try:
        with open(os.path.join(_local_data_dir(), filename), "r", encoding="utf-8") as fh:
            v = json.load(fh)
        return v if isinstance(v, type(default)) else default
    except (OSError, ValueError, TypeError):
        return default


def _save_json(filename, value):
    directory = _local_data_dir()
    os.makedirs(directory, mode=0o700, exist_ok=True)
    path = os.path.join(directory, filename)
    temp = path + ".tmp"
    with open(temp, "w", encoding="utf-8") as fh:
        json.dump(value, fh, ensure_ascii=False, indent=2)
    os.replace(temp, path)


def tool_35_historical(results):
    history = _load_json("session_history.json", [])
    history = [h for h in history if isinstance(h, dict)]
    section("Historical Results")
    print("  1. Save current session as a snapshot")
    print("  2. View saved snapshots")
    print("  3. Compare two snapshots")
    choice = ask("Select [1-3]")
    rows = []
    if choice == "1":
        if RESULTS.empty():
            rows.append(("Result", "no results to save — run a tool first"))
        else:
            snapshot = {
                "timestamp": datetime.datetime.now().isoformat(),
                "sections": [{"title": t, "lines": lines}
                             for t, lines in RESULTS.sections],
            }
            history.append(snapshot)
            history = history[-50:]
            try:
                _save_json("session_history.json", history)
                rows.append(("Saved", f"snapshot #{len(history)}"))
                rows.append(("Retention", "50 latest snapshots"))
            except OSError as exc:
                rows.append(("Error", f"save failed: {exc}"))
    elif choice == "2":
        rows.append(("Saved snapshots", str(len(history))))
        for i, snap in enumerate(history, 1):
            n = len(snap.get("sections", []))
            rows.append((f"#{i}", f"{snap.get('timestamp', '?')}  {n} sections"))
        if not history:
            rows.append(("Note", "no snapshots yet — use option 1 after running tools"))
    elif choice == "3":
        if len(history) < 2:
            rows.append(("Note", "need at least 2 saved snapshots to compare"))
        else:
            for i, snap in enumerate(history, 1):
                print(f"  #{i} {snap.get('timestamp', '?')}")
            try:
                first = int(ask("Older snapshot #"))
                second = int(ask("Newer snapshot #"))
                if not (1 <= first <= len(history) and 1 <= second <= len(history)
                        and first != second):
                    raise ValueError
                a, b = history[first - 1], history[second - 1]

                def norm(s):
                    return {sec.get("title", ""): tuple(sec.get("lines", []))
                            for sec in s.get("sections", []) if isinstance(sec, dict)}

                old, new = norm(a), norm(b)
                for title in sorted(set(old) | set(new)):
                    if title not in old:
                        rows.append((title, "ADDED"))
                    elif title not in new:
                        rows.append((title, "REMOVED"))
                    elif old[title] == new[title]:
                        rows.append((title, "unchanged"))
                    else:
                        rows.append((title, "CHANGED"))
            except (ValueError, TypeError):
                rows.append(("Error", "invalid snapshot numbers"))
    else:
        rows.append(("Result", "cancelled"))
    section("Result")
    for label, value in rows:
        print(f"  {str(label):<20}{value}")
    results.add("Historical Results", [f"{l}: {v}" for l, v in rows])
    return rows


def tool_36_batch_domains(filepath, results):
    filepath = (filepath or "").strip()
    if not filepath:
        return emit("Batch Domains", [("Error", "file path is required")], results)
    try:
        if os.path.getsize(filepath) > 1024 * 1024:
            return emit("Batch Domains", [("Error", "file >1 MiB")], results)
        with open(filepath, "r", encoding="utf-8-sig") as fh:
            raw = [ln.strip() for ln in fh if ln.strip() and not ln.strip().startswith("#")]
    except OSError as exc:
        return emit("Batch Domains", [("Error", f"{type(exc).__name__}: {exc}")], results)
    unique = list(dict.fromkeys(raw))
    if len(unique) > 50:
        return emit("Batch Domains", [("Error", f"{len(unique)} domains > 50 max")], results)
    rows = []
    for domain in unique:
        if not validate_domain(domain):
            rows.append((domain, "INVALID"))
            continue
        try:
            resp = dns_resolve(domain, "A")
            addrs = [rr["value"] for rr in resp["answers"] if rr["type"] == 1]
            rows.append((domain, ", ".join(addrs) if addrs else resp["rcode_name"]))
        except DNSError as exc:
            rows.append((domain, f"error: {exc}"))
    return emit(f"Batch Domains - {len(unique)} lines", rows, results)


def tool_37_email_deep(domain, results):
    if not validate_domain(domain):
        return emit("Email DNS Deep", [("Error", f"invalid domain: {domain}")], results)
    rows = []
    try:
        mx = [rr["value"] for rr in dns_resolve(domain, "MX")["answers"] if rr["type"] == 15]
        rows.append(("MX", f"{len(mx)} record(s)"))
        rows.extend(("", m) for m in mx[:5])
    except DNSError as exc:
        rows.append(("MX", f"error: {exc}"))
    try:
        spf = [t for t in _dns_txt(domain) if t.lower().startswith("v=spf1")]
        rows.append(("SPF", spf[0] if spf else "not found"))
    except DNSError as exc:
        rows.append(("SPF", f"error: {exc}"))
    try:
        dmarc = [t for t in _dns_txt(f"_dmarc.{domain}") if "v=dmarc1" in t.lower()]
        rows.append(("DMARC", dmarc[0] if dmarc else "not found"))
    except DNSError as exc:
        rows.append(("DMARC", f"error: {exc}"))
    for selector in ("default", "selector1", "selector2", "google", "k1", "mail"):
        try:
            recs = _dns_txt(f"{selector}._domainkey.{domain}")
            rows.append((f"DKIM {selector}", recs[0][:80] if recs else "not found"))
        except DNSError:
            rows.append((f"DKIM {selector}", "lookup error"))
    return emit(f"Email DNS Deep - {domain}", rows, results)


def tool_38_config_validator(results):
    rows = [
        ("Tool", f"{TOOL_NAME} v{VERSION}"),
        ("Author", AUTHOR),
        ("Python", sys.version.split()[0]),
        ("Platform", sys.platform),
        ("OpenSSL", ssl.OPENSSL_VERSION),
        ("DNS timeout", f"{DNS_TIMEOUT}s"),
        ("HTTP timeout", f"{HTTP_TIMEOUT}s"),
        ("Port timeout", f"{PORT_TIMEOUT}s"),
        ("Nameservers", ", ".join(_system_nameservers()) or "1.1.1.1 fallback"),
        ("Traceroute", _traceroute_capability()),
    ]
    try:
        d = _local_data_dir()
        os.makedirs(d, mode=0o700, exist_ok=True)
        probe = os.path.join(d, ".write-test")
        with open(probe, "w") as fh:
            fh.write("ok")
        os.remove(probe)
        rows.append(("Data dir write", f"OK ({d})"))
    except OSError as exc:
        rows.append(("Data dir write", f"FAILED ({type(exc).__name__})"))
    return emit("Configuration", rows, results)


def tool_39_uptime(target, checks, interval, results):
    url = normalize_url(target)
    if not url:
        return emit("Uptime History", [("Error", f"invalid URL: {target}")], results)
    try:
        checks = int(checks or 3)
        interval = float(interval or 5)
    except (TypeError, ValueError):
        return emit("Uptime History", [("Error", "invalid checks/interval")], results)
    if not (1 <= checks <= 30 and 5 <= interval <= 60):
        return emit("Uptime History", [("Error", "checks 1-30, interval 5-60s")], results)
    observations = []
    for i in range(checks):
        started = time.perf_counter()
        status = None
        ok_flag = False
        error_name = None
        try:
            resp = http_request("GET", url, allow_redirects=False, read_limit=512, timeout=5)
            status = resp["status"]
            ok_flag = status < 500
        except Exception as exc:
            error_name = type(exc).__name__
        elapsed = (time.perf_counter() - started) * 1000
        observations.append({"ts": datetime.datetime.now().isoformat(), "ok": ok_flag,
                             "status": status, "latency_ms": round(elapsed, 1),
                             "error": error_name})
        print(f"  [{i+1}/{checks}] {'UP' if ok_flag else 'DOWN'} "
              f"status={status} {elapsed:.0f}ms")
        if i + 1 < checks:
            time.sleep(interval)
    ok_count = sum(1 for o in observations if o["ok"])
    rows = [
        ("Target", url),
        ("Checks", str(checks)),
        ("Reachable", f"{ok_count}/{checks}"),
        ("Availability", f"{ok_count/checks*100:.1f}%"),
    ]
    history = _load_json("uptime_history.json", [])
    history.append({"created_at": datetime.datetime.now().isoformat(),
                    "target": url, "checks": observations})
    try:
        _save_json("uptime_history.json", history[-100:])
        rows.append(("History", f"saved ({min(len(history), 100)} runs retained)"))
    except OSError as exc:
        rows.append(("History", f"save failed ({type(exc).__name__})"))
    return emit(f"Uptime History - {url}", rows, results)


def tool_40_profiles(profile, target, results):
    profile = (profile or "basic").strip().lower()
    if profile not in {"basic", "web", "dns", "full"}:
        return emit("Profile", [("Error", "choose basic/web/dns/full")], results)
    kind, value = classify_target(target)
    if kind == "invalid":
        return emit("Profile", [("Error", f"invalid target: {target}")], results)
    rows = [("Profile", profile), ("Target", value)]
    if profile in ("basic", "full"):
        try:
            if kind == "domain":
                addrs = [rr["value"] for rr in dns_resolve(value, "A")["answers"] if rr["type"] == 1]
                rows.append(("DNS A", ", ".join(addrs) if addrs else "none"))
            else:
                rows.append(("IP", value))
        except DNSError as exc:
            rows.append(("DNS A", f"error: {exc}"))
    if profile == "dns":
        if kind == "ip":
            rows.append(("DNS profile", "requires a domain, not an IP"))
        else:
            for rtype in ("A", "AAAA", "MX", "NS"):
                try:
                    resp = dns_resolve(value, rtype)
                    cnt = sum(1 for rr in resp["answers"]
                              if rr["type"] == DNS_TYPE_CODES[rtype])
                    rows.append((rtype, f"{cnt} record(s) — {resp['rcode_name']}"))
                except DNSError as exc:
                    rows.append((rtype, f"error: {exc}"))
    if profile in ("web", "full") and kind in ("domain", "ip"):
        try:
            resp = http_request("GET", f"https://{value}", read_limit=512)
            rows.append(("HTTPS", f"{resp['status']} {resp['reason']}"))
            for h in ("strict-transport-security", "content-security-policy"):
                rows.append((h, resp["headers"].get(h, ["MISSING"])[0]))
        except Exception as exc:
            rows.append(("HTTPS", f"error: {type(exc).__name__}"))
    return emit(f"Profile - {profile}", rows, results)


def tool_41_web_ip(url, results):
    url = normalize_url(url)
    if not url:
        return emit("Web IP Checker", [("Error", f"invalid URL: {url}")], results)
    parsed = urlparse(url)
    host = parsed.hostname
    rows = [("URL", url), ("Hostname", host or "?")]
    try:
        addrs = [i[4][0] for i in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)]
        addrs = list(dict.fromkeys(addrs))
    except socket.gaierror:
        rows.append(("Error", "resolution failed"))
        return emit(f"Web IP Checker - {host}", rows, results)
    ipv4 = [a for a in addrs if ":" not in a]
    ipv6 = [a for a in addrs if ":" in a]
    rows.extend(("IPv4", a) for a in ipv4[:10])
    rows.extend(("IPv6", a) for a in ipv6[:5])
    rows.append(("Note", "may be CDN/proxy/load-balancer addresses"))
    return emit(f"Web IP Checker - {host}", rows, results)


def tool_42_internetdb(target, results):
    kind, value = classify_target(target)
    if kind == "invalid":
        return emit("InternetDB", [("Error", f"invalid target: {target}")], results)
    if kind == "domain":
        try:
            addrs = [rr["value"] for rr in dns_resolve(value, "A")["answers"] if rr["type"] == 1]
            if not addrs:
                return emit("InternetDB", [("Error", f"{value} did not resolve")], results)
            value = addrs[0]
        except DNSError as exc:
            return emit("InternetDB", [("Error", str(exc))], results)
    try:
        resp = http_request("GET", f"https://internetdb.shodan.io/{value}", read_limit=1024 * 1024)
    except Exception as exc:
        return emit("InternetDB", [("Error", f"{type(exc).__name__}: {exc}")], results)
    if resp["status"] == 404:
        return emit(f"InternetDB - {value}", [("Result", "no observations recorded")], results)
    if resp["status"] != 200:
        return emit("InternetDB", [("Error", f"HTTP {resp['status']}")], results)
    try:
        data = json.loads(resp["body"].decode("utf-8", "replace"))
    except json.JSONDecodeError:
        return emit("InternetDB", [("Error", "invalid JSON")], results)
    ports = data.get("ports") or []
    hosts = data.get("hostnames") or []
    cpes = data.get("cpes") or []
    vulns = data.get("vulns") or []
    rows = [
        ("IP", value),
        ("Ports", ", ".join(map(str, ports)) if ports else "none"),
        ("Hostnames", ", ".join(hosts) if hosts else "none"),
        ("CPEs", ", ".join(cpes[:8]) if cpes else "none"),
        ("CVEs", ", ".join(vulns[:10]) if vulns else "none"),
        ("Source", "internetdb.shodan.io"),
    ]
    return emit(f"InternetDB - {value}", rows, results)


def tool_43_banner(ip, results):
    parsed = parse_ip(ip)
    if not parsed:
        return emit("Banner Grab", [("Error", f"invalid IP: {ip}")], results)
    rows = []
    for port in BANNER_PORTS:
        if port == 443:
            rows.append((str(port), "TLS — use TLS Certificate tool"))
            continue
        banner = banner_grab(str(parsed), port)
        if banner is None:
            rows.append((str(port), "closed/unreachable"))
        elif not banner:
            rows.append((str(port), "(no banner returned)"))
        else:
            first = " | ".join(line.strip() for line in banner.splitlines()[:2] if line.strip())
            rows.append((str(port), first[:120] or "(empty)"))
    return emit(f"Banner Grab - {parsed}", rows, results)


def tool_44_zone_transfer(domain, results):
    if not validate_domain(domain):
        return emit("Zone Transfer", [("Error", f"invalid domain: {domain}")], results)
    try:
        ns_resp = dns_resolve(domain, "NS")
        nameservers = [rr["value"] for rr in ns_resp["answers"] if rr["type"] == 2]
    except DNSError as exc:
        return emit("Zone Transfer", [("Error", f"NS lookup failed: {exc}")], results)
    if not nameservers:
        return emit("Zone Transfer", [("Result", "no NS records")], results)
    rows = []
    for ns in nameservers:
        try:
            ns_ip = socket.gethostbyname(ns)
        except socket.gaierror:
            rows.append((ns, "could not resolve"))
            continue
        try:
            records = dns_axfr(ns_ip, domain)
            rows.append((f"{ns} ({ns_ip})", f"TRANSFER OK — {len(records)} records"))
            for rr in records[:15]:
                rows.append(("", f"{rr['name']} {rr['type_name']} {rr['value']}"))
        except (DNSError, OSError) as exc:
            rows.append((f"{ns} ({ns_ip})", f"refused/failed ({type(exc).__name__})"))
    rows.append(("Note", "AXFR success implies a misconfiguration"))
    return emit(f"Zone Transfer - {domain}", rows, results)


def tool_45_cname_chain(domain, results):
    if not validate_domain(domain):
        return emit("CNAME Chain", [("Error", f"invalid domain: {domain}")], results)
    rows = []
    current = domain.rstrip(".")
    seen = set()
    for _ in range(10):
        if current in seen:
            rows.append(("", f"{current} (loop)"))
            break
        seen.add(current)
        try:
            resp = dns_resolve(current, "CNAME")
        except DNSError as exc:
            rows.append(("", f"{current} (error: {exc})"))
            break
        cnames = [rr["value"] for rr in resp["answers"] if rr["type"] == 5]
        if cnames:
            rows.append(("", f"{current} -> {cnames[0]}"))
            current = cnames[0]
        else:
            rows.append(("", f"{current} (end — {resp['rcode_name']})"))
            break
    return emit(f"CNAME Chain - {domain}", rows, results)


def tool_46_tls_sans(target, results):
    kind, value = classify_target(target)
    if kind == "invalid":
        return emit("TLS SANs", [("Error", f"invalid target: {target}")], results)
    if kind == "ip":
        return emit("TLS SANs", [("Error", "requires a hostname (SNI)")], results)
    try:
        cert_info = tls_fetch_cert(value)
    except Exception as exc:
        return emit("TLS SANs", [("Error", f"{type(exc).__name__}: {exc}")], results)
    cert = cert_info["cert"]
    san = cert.get("subjectAltName", ())
    dns_names = [v for t, v in san if t == "DNS"]
    ip_addrs = [v for t, v in san if t == "IP Address"]
    rows = [("DNS SANs", str(len(dns_names)))]
    rows.extend(("", n) for n in dns_names)
    if ip_addrs:
        rows.append(("IP SANs", str(len(ip_addrs))))
        rows.extend(("", ip) for ip in ip_addrs)
    return emit(f"TLS SANs - {value}", rows, results)


def tool_47_reverse_ip(target, results):
    kind, value = classify_target(target)
    if kind == "invalid":
        return emit("Reverse IP", [("Error", f"invalid target: {target}")], results)
    if kind == "domain":
        try:
            addrs = [rr["value"] for rr in dns_resolve(value, "A")["answers"] if rr["type"] == 1]
            if not addrs:
                return emit("Reverse IP", [("Error", f"{value} did not resolve")], results)
            value = addrs[0]
        except DNSError as exc:
            return emit("Reverse IP", [("Error", str(exc))], results)
    if not validate_ip(value) or ":" in value:
        return emit("Reverse IP", [("Error", "requires IPv4")], results)
    try:
        resp = http_request(
            "GET",
            f"https://api.hackertarget.com/reverseiplookup/?q={value}",
            read_limit=512 * 1024,
        )
    except Exception as exc:
        return emit("Reverse IP", [("Error", f"{type(exc).__name__}: {exc}")], results)
    text = resp["body"].decode("utf-8", "replace").strip()
    low = text.lower()
    if "api count exceeded" in low or low.startswith("error"):
        return emit("Reverse IP", [("Provider", text[:200])], results)
    hosts = [h.strip() for h in text.splitlines() if h.strip()]
    rows = [("IP", value), ("Hosts", str(len(hosts)))]
    rows.extend(("", h) for h in hosts[:50])
    if len(hosts) > 50:
        rows.append(("", f"...{len(hosts) - 50} more"))
    rows.append(("Source", "hackertarget.com (free tier)"))
    return emit(f"Reverse IP - {value}", rows, results)


def tool_48_security_txt(target, results):
    url = normalize_url(target)
    if not url:
        return emit("Security.txt", [("Error", f"invalid URL: {target}")], results)
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    rows = []
    for path in ("/.well-known/security.txt", "/security.txt", "/robots.txt", "/sitemap.xml"):
        try:
            resp = http_request("GET", base + path, read_limit=8192)
            size = len(resp["body"])
            preview = resp["body"].decode("utf-8", "replace").splitlines()[:1]
            preview_text = preview[0][:80] if preview else ""
            rows.append((path, f"{resp['status']} ({size} bytes) {preview_text}"))
        except Exception as exc:
            rows.append((path, f"error: {type(exc).__name__}"))
    rows.append(("Note", "presence only — absence is not a vulnerability"))
    return emit(f"Security.txt - {parsed.netloc}", rows, results)


def tool_49_bulk_geo(domain, results):
    if not validate_domain(domain):
        return emit("Bulk Geo", [("Error", f"invalid domain: {domain}")], results)
    try:
        infos = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
        addrs = list(dict.fromkeys(i[4][0] for i in infos))
    except socket.gaierror:
        return emit("Bulk Geo", [("Error", "resolution failed")], results)
    rows = [("Domain", domain), ("Addresses", str(len(addrs)))]
    for ip in addrs[:8]:
        try:
            data, _ = http_get_json(f"https://ipwho.is/{ip}")
            if data.get("success"):
                conn = data.get("connection") or {}
                rows.append((ip, f"{data.get('country', '?')} / {data.get('city', '?')} — {conn.get('isp', '?')}"))
            else:
                rows.append((ip, "no data"))
        except Exception as exc:
            rows.append((ip, f"error: {type(exc).__name__}"))
    if len(addrs) > 8:
        rows.append(("", f"{len(addrs) - 8} more not geolocated (bounded to 8)"))
    return emit(f"Bulk Geo - {domain}", rows, results)


def tool_50_dnsbl(ip, results):
    parsed = parse_ip(ip)
    if not parsed or parsed.version != 4 or not parsed.is_global:
        return emit("DNSBL", [("Error", "requires a public IPv4")], results)
    reversed_octets = ".".join(reversed(str(parsed).split(".")))
    zones = [
        ("Spamhaus ZEN", "zen.spamhaus.org"),
        ("SpamCop", "bl.spamcop.net"),
        ("Barracuda", "b.barracudacentral.org"),
        ("SORBS", "dnsbl.sorbs.net"),
        ("PSBL", "psbl.surriel.com"),
        ("UCEPROTECT L1", "dnsbl-1.uceprotect.net"),
    ]
    rows = []
    for label, zone in zones:
        try:
            resp = dns_resolve(f"{reversed_octets}.{zone}", "A")
            addrs = [rr["value"] for rr in resp["answers"] if rr["type"] == 1]
            if addrs:
                rows.append((label, f"LISTED ({', '.join(addrs)})"))
            elif resp["rcode"] == 3:
                rows.append((label, "clean (NXDOMAIN)"))
            else:
                rows.append((label, f"inconclusive ({resp['rcode_name']})"))
        except DNSError as exc:
            rows.append((label, f"error: {exc}"))
    rows.append(("Note", "listing is not proof of abuse"))
    return emit(f"DNSBL - {parsed}", rows, results)


def tool_51_wayback(target, results):
    url = normalize_url(target)
    if not url:
        return emit("Wayback", [("Error", f"invalid URL: {target}")], results)
    from urllib.parse import quote
    try:
        data, _ = http_get_json(f"https://archive.org/wayback/available?url={quote(url, safe='')}")
    except Exception as exc:
        return emit("Wayback", [("Error", f"{type(exc).__name__}: {exc}")], results)
    snap = (data.get("archived_snapshots") or {}).get("closest")
    rows = [("Target", url)]
    if snap and snap.get("available"):
        rows.append(("Timestamp", snap.get("timestamp", "?")))
        rows.append(("URL", snap.get("url", "?")))
        rows.append(("Status", snap.get("status", "?")))
    else:
        rows.append(("Result", "no archived snapshot"))
    rows.append(("Source", "archive.org"))
    return emit(f"Wayback - {url}", rows, results)


def tool_52_bgp(target, results):
    parsed = parse_ip(target)
    if not parsed:
        return emit("BGP Prefix", [("Error", f"invalid IP: {target}")], results)
    try:
        data, _ = http_get_json(
            f"https://stat.ripe.net/data/prefix-overview/data.json?resource={parsed}")
    except Exception as exc:
        return emit("BGP Prefix", [("Error", f"{type(exc).__name__}: {exc}")], results)
    payload = data.get("data") or {}
    asns = payload.get("asns") or []
    rows = [("IP", str(parsed)), ("Prefix", payload.get("prefix", "?"))]
    for asn in asns[:6]:
        rows.append((f"AS{asn.get('asn', '?')}", asn.get("holder", "?")))
    rows.append(("Source", "stat.ripe.net"))
    return emit(f"BGP Prefix - {parsed}", rows, results)


def tool_53_cymru_asn(target, results):
    parsed = parse_ip(target)
    if not parsed:
        return emit("Team Cymru ASN", [("Error", f"invalid IP: {target}")], results)
    try:
        with socket.create_connection(("whois.cymru.com", 43), timeout=WHOIS_TIMEOUT) as sock:
            sock.sendall(f" -v {parsed}\r\n".encode())
            sock.settimeout(WHOIS_TIMEOUT)
            data = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
                if len(data) > 65536:
                    break
    except OSError as exc:
        return emit("Team Cymru ASN", [("Error", f"{type(exc).__name__}: {exc}")], results)
    text = data.decode("utf-8", "replace").strip()
    rows = [("IP", str(parsed))]
    for ln in text.splitlines():
        if ln.strip():
            rows.append(("", ln.strip()))
    rows.append(("Source", "whois.cymru.com:43"))
    return emit(f"Team Cymru ASN - {parsed}", rows, results)


def tool_54_cookies(url, results):
    url = normalize_url(url)
    if not url:
        return emit("Cookie Security", [("Error", f"invalid URL: {url}")], results)
    try:
        resp = http_request("GET", url, read_limit=512)
    except Exception as exc:
        return emit("Cookie Security", [("Error", f"{type(exc).__name__}: {exc}")], results)
    cookies = []
    for k, v in resp["raw_headers"]:
        if k.lower() == "set-cookie":
            cookies.append(v)
    rows = [("Status", str(resp["status"])), ("Cookies", str(len(cookies)))]
    for cookie in cookies:
        parts = [p.strip() for p in cookie.split(";")]
        name = parts[0].split("=", 1)[0]
        low = " ".join(parts[1:]).lower()
        secure = "secure" in low
        httponly = "httponly" in low
        samesite = "not set"
        for p in parts[1:]:
            if p.lower().startswith("samesite="):
                samesite = p.split("=", 1)[1]
                break
        rows.append((name, f"{'Secure' if secure else 'NOT-Secure'}, "
                            f"{'HttpOnly' if httponly else 'NOT-HttpOnly'}, SameSite={samesite}"))
    return emit(f"Cookie Security - {url}", rows, results)


def tool_55_cors(url, results):
    url = normalize_url(url)
    if not url:
        return emit("CORS", [("Error", f"invalid URL: {url}")], results)
    try:
        resp = http_request("GET", url, headers={"Origin": "https://example.com"},
                            allow_redirects=False, read_limit=512)
    except Exception as exc:
        return emit("CORS", [("Error", f"{type(exc).__name__}: {exc}")], results)
    acao = resp["headers"].get("access-control-allow-origin", ["(not set)"])[0]
    acac = resp["headers"].get("access-control-allow-credentials", ["(not set)"])[0]
    rows = [
        ("Status", str(resp["status"])),
        ("ACAO", acao),
        ("ACAC", acac),
        ("ACAM", resp["headers"].get("access-control-allow-methods", ["(not set)"])[0]),
        ("ACAH", resp["headers"].get("access-control-allow-headers", ["(not set)"])[0]),
    ]
    if acao == "*" and acac.lower() == "true":
        rows.append(("Warning", "wildcard origin with credentials"))
    return emit(f"CORS - {url}", rows, results)


def tool_56_wildcard_dns(domain, results):
    if not validate_domain(domain):
        return emit("Wildcard DNS", [("Error", f"invalid domain: {domain}")], results)
    label = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=12))
    probe = f"{label}.{domain}"
    try:
        resp = dns_resolve(probe, "A")
    except DNSError as exc:
        return emit("Wildcard DNS", [("Error", str(exc))], results)
    addrs = [rr["value"] for rr in resp["answers"] if rr["type"] == 1]
    rows = [("Probe", probe)]
    if addrs:
        rows.append(("Result", f"WILDCARD detected -> {', '.join(addrs)}"))
    elif resp["rcode"] == 3:
        rows.append(("Result", "no wildcard (NXDOMAIN)"))
    else:
        rows.append(("Result", f"no A records ({resp['rcode_name']})"))
    return emit(f"Wildcard DNS - {domain}", rows, results)


_TAKEOVER_FINGERPRINTS = {
    "github.io": ["There isn't a GitHub Pages site here"],
    "herokuapp.com": ["No such app"],
    "azurewebsites.net": ["404 Web Site not found"],
    "cloudfront.net": ["ERROR: The request could not be satisfied"],
    "fastly.net": ["Fastly error: unknown domain"],
    "s3.amazonaws.com": ["NoSuchBucket"],
    "bitbucket.io": ["Repository not found"],
    "wordpress.com": ["Do you want to register"],
    "tumblr.com": ["There's nothing here"],
    "myshopify.com": ["Sorry, this shop is currently unavailable"],
    "pantheonsite.io": ["The gods are wise"],
    "readthedocs.io": ["This domain is not configured"],
    "surge.sh": ["project not found"],
    "ghost.io": ["Domain error"],
}


def tool_57_takeover(domain, results):
    if not validate_domain(domain):
        return emit("Takeover", [("Error", f"invalid domain: {domain}")], results)
    rows = []
    try:
        resp = dns_resolve(domain, "CNAME")
    except DNSError as exc:
        return emit("Takeover", [("Error", str(exc))], results)
    cnames = [rr["value"] for rr in resp["answers"] if rr["type"] == 5]
    if not cnames:
        rows.append(("CNAME", "none"))
        return emit(f"Takeover - {domain}", rows, results)
    target = cnames[0]
    rows.append(("CNAME", target))
    match = next((k for k in _TAKEOVER_FINGERPRINTS if target.endswith(k)), None)
    if not match:
        rows.append(("Result", "not a known-takeoverable service"))
        return emit(f"Takeover - {domain}", rows, results)
    rows.append(("Service", match))
    try:
        http_resp = http_request("GET", f"http://{domain}", read_limit=8192)
        body = http_resp["body"].decode("utf-8", "replace")
        for fp in _TAKEOVER_FINGERPRINTS[match]:
            if fp in body:
                rows.append(("CONFIRMED", f"matched '{fp[:60]}'"))
                return emit(f"Takeover - {domain}", rows, results)
        rows.append(("Result", "CNAME matches but body does not"))
    except Exception as exc:
        rows.append(("Fetch", f"error: {type(exc).__name__}"))
    return emit(f"Takeover - {domain}", rows, results)


def tool_58_basic_auth(url, results):
    url = normalize_url(url)
    if not url:
        return emit("Basic Auth", [("Error", f"invalid URL: {url}")], results)
    try:
        resp = http_request("GET", url, allow_redirects=False, read_limit=512)
    except Exception as exc:
        return emit("Basic Auth", [("Error", f"{type(exc).__name__}: {exc}")], results)
    auth = resp["headers"].get("www-authenticate", [""])[0]
    rows = [("Status", str(resp["status"])), ("WWW-Authenticate", auth or "(not set)")]
    if resp["status"] == 401:
        low = auth.lower()
        if low.startswith("basic"):
            rows.append(("Result", "HTTP Basic enforced"))
        elif low.startswith("digest"):
            rows.append(("Result", "HTTP Digest enforced"))
        elif low.startswith("bearer"):
            rows.append(("Result", "Bearer required"))
        else:
            rows.append(("Result", "401 no recognized scheme"))
    elif resp["status"] in (301, 302, 303, 307, 308):
        rows.append(("Result", "redirect — follow manually"))
    else:
        rows.append(("Result", "no auth challenge on this path"))
    return emit(f"Basic Auth - {url}", rows, results)


def tool_59_tls_expiry(target, results):
    kind, value = classify_target(target)
    if kind == "invalid":
        return emit("TLS Expiry", [("Error", f"invalid target: {target}")], results)
    if kind == "ip":
        return emit("TLS Expiry", [("Error", "requires a hostname (SNI)")], results)
    try:
        cert_info = tls_fetch_cert(value)
    except Exception as exc:
        return emit("TLS Expiry", [("Error", f"{type(exc).__name__}: {exc}")], results)
    cert = cert_info["cert"]
    subject = dict(item[0] for item in cert.get("subject", ()))
    not_after = cert.get("notAfter", "")
    rows = [("Subject", subject.get("commonName", "?")),
            ("notBefore", cert.get("notBefore", "?")),
            ("notAfter", not_after)]
    try:
        expiry = ssl.cert_time_to_seconds(not_after)
        days = (expiry - time.time()) / 86400
        rows.append(("Days left", f"{days:.1f}"))
        if days < 0:
            rows.append(("WARNING", "certificate EXPIRED"))
        elif days < 14:
            rows.append(("WARNING", "expires within 14 days"))
        elif days < 30:
            rows.append(("WARNING", "expires within 30 days"))
        else:
            rows.append(("Status", "valid > 30 days"))
    except Exception as exc:
        rows.append(("Parse", f"error: {type(exc).__name__}"))
    return emit(f"TLS Expiry - {value}", rows, results)


def export_txt(target):
    if RESULTS.empty():
        warn("no results — run a tool first")
        return
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", target or "session")
    default = f"{safe}_ipfinder_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    filename = ask(f"filename [{default}]") or default
    try:
        with open(filename, "w", encoding="utf-8") as fh:
            fh.write(RESULTS.render(target))
        ok(f"saved to {filename}")
    except OSError as exc:
        err(f"write failed: {exc}")


def export_json(target):
    if RESULTS.empty():
        warn("no results — run a tool first")
        return
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", target or "session")
    default = f"{safe}_ipfinder_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    filename = ask(f"filename [{default}]") or default
    payload = {
        "tool": TOOL_NAME, "version": VERSION,
        "timestamp": datetime.datetime.now().isoformat(),
        "target": target,
        "results": [{"title": t, "lines": lines} for t, lines in RESULTS.sections],
    }
    try:
        with open(filename, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        ok(f"saved to {filename}")
    except OSError as exc:
        err(f"write failed: {exc}")


def menu():
    return [
        "[::] SELECT A NETWORK TOOL [::]", "",
        f"{DRED}[01]{RESET} Public IP Lookup       {DRED}[09]{RESET} TLS Certificate",
        f"{DRED}[02]{RESET} Reverse DNS            {DRED}[10]{RESET} Subdomain Discovery",
        f"{DRED}[03]{RESET} Domain to IP           {DRED}[11]{RESET} ASN / ISP Lookup",
        f"{DRED}[04]{RESET} DNS Records            {DRED}[12]{RESET} RDAP Lookup",
        f"{DRED}[05]{RESET} GeoIP Lookup           {DRED}[13]{RESET} DNS Propagation",
        f"{DRED}[06]{RESET} WHOIS Lookup           {DRED}[14]{RESET} DNSSEC Inspection",
        f"{DRED}[07]{RESET} Common Port Scan       {DRED}[15]{RESET} Subnet Calculator",
        f"{DRED}[08]{RESET} HTTP Headers", "",
        f"{CYAN}EXTENDED{RESET}",
        f"{DRED}[16]{RESET} IP Reputation          {DRED}[21]{RESET} CDN / WAF Detector",
        f"{DRED}[17]{RESET} Email Domain Security  {DRED}[22]{RESET} Redirect Chain",
        f"{DRED}[18]{RESET} HTTP Diagnostics       {DRED}[23]{RESET} HTTP Performance",
        f"{DRED}[19]{RESET} Local Network Info     {DRED}[24]{RESET} Certificate Transparency",
        f"{DRED}[20]{RESET} DNS TTL                {DRED}[25]{RESET} Security Headers",
        f"{DRED}[26]{RESET} Latency                {DRED}[31]{RESET} Connection Stability",
        f"{DRED}[27]{RESET} DNS Health             {DRED}[32]{RESET} TLS Compatibility",
        f"{DRED}[28]{RESET} Smart Diagnostic       {DRED}[33]{RESET} HTTP Method Checker",
        f"{DRED}[29]{RESET} DNS Comparison         {DRED}[34]{RESET} IPv6 Readiness",
        f"{DRED}[30]{RESET} Traceroute (built-in)  {DRED}[35]{RESET} Historical Results",
        f"{DRED}[36]{RESET} Batch Domains          {DRED}[39]{RESET} Uptime History",
        f"{DRED}[37]{RESET} Email DNS Deep         {DRED}[40]{RESET} Diagnostic Profiles",
        f"{DRED}[38]{RESET} Config Validator       {DRED}[41]{RESET} Web IP Checker", "",
        f"{CYAN}PASSIVE RECON{RESET}",
        f"{DRED}[42]{RESET} Shodan InternetDB      {DRED}[46]{RESET} TLS SAN Extractor",
        f"{DRED}[43]{RESET} Port Banner Grab       {DRED}[47]{RESET} Reverse IP Lookup",
        f"{DRED}[44]{RESET} DNS Zone Transfer      {DRED}[48]{RESET} Security.txt / robots",
        f"{DRED}[45]{RESET} CNAME Chain Tracer     {DRED}[49]{RESET} Bulk IP Geolocation", "",
        f"{CYAN}RECON EXTENDED{RESET}",
        f"{DRED}[50]{RESET} DNSBL Checker          {DRED}[55]{RESET} CORS Policy",
        f"{DRED}[51]{RESET} Wayback Machine        {DRED}[56]{RESET} Wildcard DNS",
        f"{DRED}[52]{RESET} BGP Prefix (RIPEstat)  {DRED}[57]{RESET} Subdomain Takeover",
        f"{DRED}[53]{RESET} Team Cymru ASN         {DRED}[58]{RESET} Basic Auth",
        f"{DRED}[54]{RESET} Cookie Security        {DRED}[59]{RESET} TLS Expiry", "",
        f"{DRED}[90]{RESET} Export TXT     {DRED}[91]{RESET} Export JSON",
        f"{DRED}[99]{RESET} About / Deps   {DRED}[00]{RESET} Exit",
    ]


def show_menu():
    clear_screen()
    banner()
    print(f"{CYAN}Status:{RESET} {GREEN}Ready (pure stdlib){RESET}\n")
    for line in menu():
        print(f"  {line}")
    print()


def about():
    section("About")
    rows = [
        ("Tool", f"{TOOL_NAME} v{VERSION}"),
        ("Author", AUTHOR),
        ("Dependencies", "Python 3.10+ standard library ONLY"),
        ("DNS", "custom wire-format resolver (UDP + TCP)"),
        ("HTTP", "http.client + ssl"),
        ("WHOIS", "custom port-43 referral chain"),
        ("Traceroute", "ICMP raw / TCP SYN via IP_RECVERR"),
        ("Sources", "ipify, ipwho.is, rdap.org, crt.sh, internetdb.shodan.io, "
                    "stat.ripe.net, whois.cymru.com, hackertarget, archive.org, "
                    "ipaddress.to, DNSBL zones, public resolvers"),
        ("Responsible use", "only targets you own or have permission to inspect"),
    ]
    for k, v in rows:
        print(f"  {k:<16}{v}")


def dispatch(choice):
    if choice == "01": return tool_01_public_ip(RESULTS)
    if choice == "02": return tool_02_reverse_dns(ask("Target IP"), RESULTS)
    if choice == "03": return tool_03_domain_to_ip(ask("Target Domain"), RESULTS)
    if choice == "04": return tool_04_dns_records(ask("Target Domain"), RESULTS)
    if choice == "05": return tool_05_geoip(ask("Target IP"), RESULTS)
    if choice == "06": return tool_06_whois(ask("Target Domain or IP"), RESULTS)
    if choice == "07": return tool_07_port_scan(ask("Target IP"), RESULTS)
    if choice == "08": return tool_08_http_headers(ask("Target URL/host"), RESULTS)
    if choice == "09": return tool_09_tls_cert(ask("Target hostname"), RESULTS)
    if choice == "10": return tool_10_subdomains(ask("Target Domain"), RESULTS)
    if choice == "11": return tool_11_asn(ask("Target IP or Domain"), RESULTS)
    if choice == "12": return tool_12_rdap(ask("Target IP or Domain"), RESULTS)
    if choice == "13":
        d = ask("Target Domain"); r = ask("Record type [A]") or "A"
        return tool_13_propagation(d, r, RESULTS)
    if choice == "14": return tool_14_dnssec(ask("Target Domain"), RESULTS)
    if choice == "15": return tool_15_subnet(ask("CIDR"), RESULTS)
    if choice == "16": return tool_16_ip_reputation(ask("Public IP"), RESULTS)
    if choice == "17":
        d = ask("Email domain"); s = ask("DKIM selector (optional)") or None
        return tool_17_email_security(d, s, RESULTS)
    if choice == "18": return tool_18_http_diag(ask("Target URL"), RESULTS)
    if choice == "19": return tool_19_local_network(RESULTS)
    if choice == "20":
        d = ask("Target Domain"); r = ask("Record type [A]") or "A"
        return tool_20_ttl(d, r, RESULTS)
    if choice == "21": return tool_21_cdn_waf(ask("Target URL"), RESULTS)
    if choice == "22": return tool_22_redirects(ask("Target URL"), RESULTS)
    if choice == "23": return tool_23_http_perf(ask("Target URL"), RESULTS)
    if choice == "24": return tool_24_ct(ask("Target Domain"), RESULTS)
    if choice == "25": return tool_25_security_headers(ask("Target URL"), RESULTS)
    if choice == "26": return tool_26_latency(ask("Target host/IP"), RESULTS)
    if choice == "27": return tool_27_dns_health(ask("Target Domain"), RESULTS)
    if choice == "28": return tool_28_smart(ask("Target"), RESULTS)
    if choice == "29":
        d = ask("Target Domain"); r = ask("Record type [A]") or "A"
        return tool_29_dns_compare(d, r, RESULTS)
    if choice == "30": return tool_30_traceroute(ask("Target host"), RESULTS)
    if choice == "31":
        t = ask("Target host"); p = ask("Port [443]") or "443"
        s = ask("Samples (1-30) [5]") or "5"; i = ask("Interval seconds [2]") or "2"
        return tool_31_connection_stability(t, p, s, i, RESULTS)
    if choice == "32":
        t = ask("Target host"); p = ask("TLS port [443]") or "443"
        return tool_32_tls_compat(t, p, RESULTS)
    if choice == "33": return tool_33_http_method(ask("Target URL"), RESULTS)
    if choice == "34": return tool_34_ipv6_readiness(ask("Target Domain"), RESULTS)
    if choice == "35": return tool_35_historical(RESULTS)
    if choice == "36": return tool_36_batch_domains(ask("Path to domain list"), RESULTS)
    if choice == "37": return tool_37_email_deep(ask("Email domain"), RESULTS)
    if choice == "38": return tool_38_config_validator(RESULTS)
    if choice == "39":
        t = ask("Target URL"); c = ask("Checks (1-30) [3]") or "3"
        i = ask("Interval seconds (5-60) [5]") or "5"
        return tool_39_uptime(t, c, i, RESULTS)
    if choice == "40":
        p = ask("Profile [basic/web/dns/full]") or "basic"
        t = ask("Target")
        return tool_40_profiles(p, t, RESULTS)
    if choice == "41": return tool_41_web_ip(ask("Target URL"), RESULTS)
    if choice == "42": return tool_42_internetdb(ask("Target IP or Domain"), RESULTS)
    if choice == "43": return tool_43_banner(ask("Target IP"), RESULTS)
    if choice == "44": return tool_44_zone_transfer(ask("Target Domain"), RESULTS)
    if choice == "45": return tool_45_cname_chain(ask("Target Domain"), RESULTS)
    if choice == "46": return tool_46_tls_sans(ask("Target hostname"), RESULTS)
    if choice == "47": return tool_47_reverse_ip(ask("Target IP or Domain"), RESULTS)
    if choice == "48": return tool_48_security_txt(ask("Target URL/host"), RESULTS)
    if choice == "49": return tool_49_bulk_geo(ask("Target Domain"), RESULTS)
    if choice == "50": return tool_50_dnsbl(ask("Public IPv4"), RESULTS)
    if choice == "51": return tool_51_wayback(ask("Target URL"), RESULTS)
    if choice == "52": return tool_52_bgp(ask("Target IP"), RESULTS)
    if choice == "53": return tool_53_cymru_asn(ask("Target IP"), RESULTS)
    if choice == "54": return tool_54_cookies(ask("Target URL"), RESULTS)
    if choice == "55": return tool_55_cors(ask("Target URL"), RESULTS)
    if choice == "56": return tool_56_wildcard_dns(ask("Target Domain"), RESULTS)
    if choice == "57": return tool_57_takeover(ask("Subdomain"), RESULTS)
    if choice == "58": return tool_58_basic_auth(ask("Target URL"), RESULTS)
    if choice == "59": return tool_59_tls_expiry(ask("Target hostname"), RESULTS)
    if choice == "90":
        export_txt(ask("Export label") or "session")
        return
    if choice == "91":
        export_json(ask("Export label") or "session")
        return
    if choice == "99":
        about()
        return
    if choice == "00":
        print(f"\n{CYAN}Goodbye.{RESET}")
        sys.exit(0)
    err(f"unknown option: {choice}")


def main():
    while True:
        try:
            show_menu()
            try:
                choice = input(f"{GREEN}[~]{RESET} Select [00-99]: ").strip()
            except EOFError:
                print(f"\n{CYAN}Goodbye.{RESET}")
                return
            dispatch(choice)
        except KeyboardInterrupt:
            print(f"\n{CYAN}Interrupted.{RESET}")
            return
        except Exception as exc:
            err(f"unexpected: {type(exc).__name__}: {exc}")
        pause()


if __name__ == "__main__":
    main()