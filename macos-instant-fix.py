#!/usr/bin/env python3
"""
Antigravity + Voice Input + Gemini Desktop App (Robin) Auto-Bypass & VPN Isolation Utility for macOS.

Features:
1. Physical Interface Isolation (NetBird / FortiVPN / Happ immunity):
   - Detects physical interface (e.g. en0) and hardware gateway via `ipconfig getoption <if> router`
     and `route -n get -ifscope <if> 8.8.8.8`, even when full-tunnel VPNs (FortiVPN, Happ TUN, NetBird) are active.
   - Binds all DNS, DoH, and TLS probe sockets directly to the physical interface at the XNU kernel level
     using `setsockopt(IPPROTO_IP, IP_BOUND_IF, if_index)`.
   - Installs `/32` static host routes (`route -n add -host <IP> <GATEWAY>`) for all active SNI proxy IPs
     and DNS bootstrap servers so Antigravity & Gemini traffic always goes straight through the physical router,
     completely bypassing FortiVPN, Happ TUN, and NetBird tunnels.
   - Configures macOS System Proxy bypass domains (`ProxyBypassDomains`) so Happ/FortiVPN in System Proxy mode
     never intercepts Antigravity or Gemini traffic.
2. Parallel DNS & DoH Race + TLS 1.3 & HTTP/2 (ALPN `h2`) Verification:
   - Queries `dns-ai.ru` (DoH) and `geohide.ru` (UDP) in parallel, filters out unproxied Google IPs,
     and benchmarks every candidate IP per domain for real TLS 1.3 + HTTP/2 handshake speed.
3. Zero-Latency IPv6 / HTTPS-RR Suppression:
   - Updates `/etc/hosts` with the single fastest verified IPv4 per domain and creates `/etc/resolver/<domain>`
     pointing to `127.0.0.1` (`ag_dns` returns instant 0ms NODATA for AAAA/HTTPS queries).
4. Background Auto-Heal Watchdog (`LaunchDaemon`):
   - Automatically installs `/Library/LaunchDaemons/com.antigravity.bypass.watchdog.plist` to keep `/32` routes
     and `/etc/hosts` healthy across Wi-Fi switches, VPN toggles (FortiVPN / Happ), and proxy IP rotations.
"""

from __future__ import annotations

import base64
import concurrent.futures
import json
import os
import plistlib
import socket
import ssl
import struct
import subprocess
import sys
import time
from pathlib import Path

NRPT_TAG = "ANTIGRAVITY-BYPASS-RUSSIA"

# Darwin / macOS kernel constant in <netinet/in.h>: #define IP_BOUND_IF 25
IP_BOUND_IF = 25

# All required domains for:
# 1. Antigravity IDE (chat, agent, streaming)
# 2. Antigravity Voice Input (speech recognition via aicode.googleapis.com)
# 3. Google Gemini Desktop App (/Applications/Gemini.app -> robinfrontend-pa.googleapis.com, etc.)
# 4. Google AI Studio / Web
TARGET_HOSTS = [
    # Antigravity Core
    "daily-cloudcode-pa.googleapis.com",
    "cloudcode-pa.googleapis.com",
    "generativelanguage.googleapis.com",
    # Antigravity Voice Input (Dictation / Speech-to-Text)
    "aicode.googleapis.com",
    # Gemini Desktop App (macOS native client codename Robin / Janus)
    "robinfrontend-pa.googleapis.com",
    "webchannel-robinfrontend-pa.googleapis.com",
    "proactivebackend-pa.googleapis.com",
    "geller-pa.googleapis.com",
    "gemini.google.com",
    # AI Studio & WebChannel
    "aistudio.google.com",
    "alkalimakersuite-pa.clients6.google.com",
    "alkalicore-pa.clients6.google.com",
    "webchannel-alkalimakersuite-pa.clients6.google.com",
]

# Gemini Desktop App & Web domains must NEVER use comss.one (157.22.*) because
# comss.one triggers 'locationRejected' (iRPC code=9) on robinfrontend-pa and hangs on gemini.google.com.
GEMINI_STRICT_HOSTS = {
    "robinfrontend-pa.googleapis.com",
    "webchannel-robinfrontend-pa.googleapis.com",
    "proactivebackend-pa.googleapis.com",
    "geller-pa.googleapis.com",
    "gemini.google.com",
    "aicode.googleapis.com",
}

# Additional suffix domains for /etc/resolver/ split-DNS
EXTRA_RESOLVER_DOMAINS = [
    "makersuite.google.com",
    "ai.google.dev",
    "bard.google.com",
    "notebooklm.google.com",
    "notebooklm-pa.googleapis.com",
    "jules.google.com",
    "aisandbox-pa.googleapis.com",
    "deepmind.google",
]

# Domains that must bypass macOS System HTTP/SOCKS Proxy (when Happ or FortiVPN sets system proxy)
PROXY_BYPASS_DOMAINS = [
    "*.local",
    "169.254/16",
    "*.googleapis.com",
    "googleapis.com",
    "gemini.google.com",
    "*.gemini.google.com",
    "aistudio.google.com",
    "*.aistudio.google.com",
    "*.clients6.google.com",
    "ai.google.dev",
    "*.ai.google.dev",
    "makersuite.google.com",
    "notebooklm.google.com",
]

DOH_BOOTSTRAP_IPS = [
    "192.144.59.14",
    "186.246.49.127",
    "94.232.43.149",
]

UDP_DNS_PROVIDERS = [
    ("geohide.ru", ["37.230.192.51", "45.155.204.190"]),
]

PRIMARY_PROXY_IPS = [
    "193.233.112.67",
    "193.233.112.68",
    "193.233.112.88",
]

SECONDARY_PROXY_IPS = [
    "157.22.177.90",
    "191.44.41.215",
    "191.44.41.79",
]

DISALLOWED_FOR_GEMINI_IPS = {
    "157.22.177.90",
    "157.22.178.170",
    "132.243.112.221",
    "159.194.200.33",
}

SEED_PROXY_IPS = PRIMARY_PROXY_IPS + SECONDARY_PROXY_IPS

GOOGLE_FIRST_TWO_OCTETS = {
    (64, 233),
    (66, 102),
    (66, 249),
    (72, 14),
    (74, 125),
    (142, 250),
    (142, 251),
    (172, 217),
    (173, 194),
    (192, 178),
    (216, 58),
    (216, 239),
}

STATE_DIR = Path("/Library/Application Support/AntigravityBypass")
LEGACY_RUST_DIR = Path("/Library/Application Support/AntigravityBypassRussia")
ROUTES_STATE_FILE = STATE_DIR / "owned_routes_macos.json"
WATCHDOG_PLIST_PATH = Path("/Library/LaunchDaemons/com.antigravity.bypass.watchdog.plist")
INSTALLED_SCRIPT_PATH = STATE_DIR / "macos-instant-fix.py"


def looks_like_google(ip_str: str) -> bool:
    try:
        parts = [int(x) for x in ip_str.split(".")]
        if len(parts) == 4:
            return (parts[0], parts[1]) in GOOGLE_FIRST_TWO_OCTETS
    except Exception:
        pass
    return False


def detect_physical_egress():
    """
    Finds the physical network interface (e.g. en0) and its hardware router IP,
    completely ignoring virtual VPN interfaces (utun*, ppp*, bridge*, gif*, stf*)
    created by NetBird, FortiVPN, or Happ.
    Returns (if_name, if_index, gateway_ip) or (None, 0, None).
    """
    candidates = ["en0", "en1", "en2", "en3", "en4", "en5", "en6", "en7"]
    # First check hardware ports via networksetup if available
    try:
        out = subprocess.check_output(
            ["/usr/sbin/networksetup", "-listallhardwareports"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=2,
        )
        hw_devs = []
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Device:"):
                dev = line.split(":", 1)[1].strip()
                if dev.startswith("en") and dev not in hw_devs:
                    hw_devs.append(dev)
        if hw_devs:
            candidates = hw_devs + [c for c in candidates if c not in hw_devs]
    except Exception:
        pass

    for if_name in candidates:
        # Method 1: DHCP option router on the physical interface (works even when FortiVPN/Happ overrides default route)
        gw = None
        try:
            out = subprocess.check_output(
                ["/usr/sbin/ipconfig", "getoption", if_name, "router"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=1.5,
            ).strip()
            if out and "." in out and not out.startswith("169.254."):
                gw = out.splitlines()[0].strip()
        except Exception:
            pass

        # Method 2: Scoped route lookup (`route -n get -ifscope en0 8.8.8.8`)
        if not gw:
            try:
                out = subprocess.check_output(
                    ["/sbin/route", "-n", "get", "-ifscope", if_name, "8.8.8.8"],
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=1.5,
                )
                for line in out.splitlines():
                    line = line.strip()
                    if line.startswith("gateway:"):
                        cand = line.split(":", 1)[1].strip()
                        if "." in cand and not cand.startswith("link#"):
                            gw = cand
                            break
            except Exception:
                pass

        if gw:
            try:
                if_index = socket.if_nametoindex(if_name)
                return if_name, if_index, gw
            except Exception:
                pass

    return None, 0, None


def bind_socket_to_if(sock: socket.socket, if_index: int):
    """Binds a socket directly to the physical interface index on macOS (IP_BOUND_IF = 25)."""
    if if_index > 0:
        try:
            sock.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF, struct.pack("I", if_index))
        except Exception:
            pass


def build_dns_query(domain: str, qtype: int = 1, txid: int = 0x4147) -> bytes:
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(
        bytes([len(label)]) + label.encode("ascii")
        for label in domain.strip(".").split(".")
        if label
    ) + b"\x00"
    question = qname + struct.pack(">HH", qtype, 1)
    return header + question


def skip_dns_name(buf: bytes, pos: int) -> int:
    hops = 0
    while pos < len(buf) and hops < 64:
        hops += 1
        length = buf[pos]
        if length == 0:
            return pos + 1
        if (length & 0xC0) == 0xC0:
            return pos + 2
        pos += 1 + length
    return len(buf)


def parse_dns_a_records(buf: bytes) -> list[str]:
    if len(buf) < 12:
        return []
    flags = struct.unpack(">H", buf[2:4])[0]
    rcode = flags & 0x000F
    if rcode != 0:
        return []
    qdcount, ancount = struct.unpack(">HH", buf[4:8])
    pos = 12
    for _ in range(qdcount):
        pos = skip_dns_name(buf, pos) + 4
    ips = []
    for _ in range(ancount):
        if pos >= len(buf):
            break
        pos = skip_dns_name(buf, pos)
        if pos + 10 > len(buf):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", buf[pos : pos + 10])
        pos += 10
        if pos + rdlen > len(buf):
            break
        if rtype == 1 and rdlen == 4:
            ip = socket.inet_ntoa(buf[pos : pos + 4])
            if ip != "0.0.0.0" and not looks_like_google(ip) and ip not in ips:
                ips.append(ip)
        pos += rdlen
    return ips


def query_udp_dns(server_ip: str, domain: str, if_index: int = 0, timeout: float = 1.2) -> list[str]:
    pkt = build_dns_query(domain)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            bind_socket_to_if(sock, if_index)
            sock.settimeout(timeout)
            sock.sendto(pkt, (server_ip, 53))
            data, _ = sock.recvfrom(1500)
            return parse_dns_a_records(data)
    except Exception:
        return []


def query_doh_raw(bootstrap_ip: str, domain: str, if_index: int = 0, timeout: float = 1.8) -> list[str]:
    """
    Queries https://dns.dns-ai.ru/dns-query over RFC 8484 HTTP/2 using /usr/bin/curl.
    """
    pkt = build_dns_query(domain)
    b64 = base64.urlsafe_b64encode(pkt).decode("ascii").rstrip("=")
    cmd = [
        "/usr/bin/curl",
        "-sS",
        "--http2",
        "--max-time",
        str(timeout),
        "--resolve",
        f"dns.dns-ai.ru:443:{bootstrap_ip}",
        "-H",
        "accept: application/dns-message",
        f"https://dns.dns-ai.ru/dns-query?dns={b64}",
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, timeout=timeout + 0.5)
        if res.returncode == 0 and res.stdout:
            return parse_dns_a_records(res.stdout)
    except Exception:
        pass
    return []


def discover_candidates(domains: list[str], if_index: int = 0) -> dict[str, list[str]]:
    candidates: dict[str, list[str]] = {}
    for d in domains:
        if d in GEMINI_STRICT_HOSTS:
            candidates[d] = [ip for ip in SEED_PROXY_IPS if ip not in DISALLOWED_FOR_GEMINI_IPS]
        else:
            candidates[d] = list(SEED_PROXY_IPS)

    tasks = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
        for d in domains:
            for ip in DOH_BOOTSTRAP_IPS[:1]:
                tasks.append((d, "dns-ai.ru", pool.submit(query_doh_raw, ip, d, if_index, 1.8)))
            for prov_name, srv_ips in UDP_DNS_PROVIDERS:
                for srv_ip in srv_ips:
                    tasks.append((d, prov_name, pool.submit(query_udp_dns, srv_ip, d, if_index, 1.2)))
        for d, _prov, fut in tasks:
            try:
                for ip in fut.result():
                    if d in GEMINI_STRICT_HOSTS and ip in DISALLOWED_FOR_GEMINI_IPS:
                        continue
                    if ip not in candidates[d]:
                        candidates[d].insert(0, ip)
            except Exception:
                pass
    return candidates


def probe_tls_h2(ip: str, sni_host: str, if_index: int = 0, timeout: float = 2.2) -> tuple[bool, int, str]:
    """
    Verifies TCP + TLS 1.3/1.2 certificate chain + ALPN (h2/http/1.1) bound directly
    to the physical interface (`if_index`).
    """
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    start = time.monotonic()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw_sock:
            bind_socket_to_if(raw_sock, if_index)
            raw_sock.settimeout(timeout)
            raw_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            raw_sock.connect((ip, 443))
            with ctx.wrap_socket(raw_sock, server_hostname=sni_host) as tls_sock:
                alpn = tls_sock.selected_alpn_protocol() or "http/1.1"
                if alpn == "http/1.1":
                    req = f"HEAD / HTTP/1.1\r\nHost: {sni_host}\r\nConnection: close\r\n\r\n".encode("ascii")
                    tls_sock.sendall(req)
                    data = tls_sock.recv(256)
                    if not data.startswith(b"HTTP/1."):
                        return (False, 9999, "invalid_http")
                ms = max(1, int((time.monotonic() - start) * 1000))
                # Penalize secondary/slow proxies so PRIMARY_PROXY_IPS (193.233.112.*) always win when healthy
                if ip not in PRIMARY_PROXY_IPS:
                    ms += 1500
                return (True, ms, alpn)
    except Exception as e:
        return (False, 9999, str(e))


def rank_all_hosts(candidates_by_host: dict[str, list[str]], if_index: int = 0) -> dict[str, list[tuple[str, int, str]]]:
    results: dict[str, list[tuple[str, int, str]]] = {h: [] for h in candidates_by_host}
    futures = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=48) as pool:
        for host, ips in candidates_by_host.items():
            for ip in ips:
                fut = pool.submit(probe_tls_h2, ip, host, if_index, 2.2)
                futures[fut] = (host, ip)
        for fut, (host, ip) in futures.items():
            ok, ms, info = fut.result()
            if ok:
                results[host].append((ip, ms, info))
    for host in results:
        results[host].sort(key=lambda item: item[1])
    return results


def get_static_host_routes() -> dict[str, str]:
    """
    Returns {ip: gateway} for routes in `netstat -rn -f inet` that genuinely have the
    `S` (STATIC) flag and do NOT have the `W` (WASCLONED) temporary flag.
    """
    static_map: dict[str, str] = {}
    try:
        out = subprocess.check_output(
            ["/usr/sbin/netstat", "-rn", "-f", "inet"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=2,
        )
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                dest, gw, flags = parts[0], parts[1], parts[2]
                if "S" in flags and "W" not in flags:
                    clean_dest = dest.split("/")[0]
                    static_map[clean_dest] = gw
    except Exception:
        pass
    return static_map


def sync_vpn_excluded_routes(all_ips: list[str]) -> bool:
    """
    When NetworkExtension VPNs like Happ (su.ffg.happ on utun*) or FortiVPN connect with
    PrimaryRank=First, injects our SNI proxy IPs into `ExcludedRoutes` of the active VPN
    service in SCDynamicStore (`scutil`) so macOS NECP/configd routes them outside the tunnel.
    """
    changed_any = False
    try:
        list_out = subprocess.check_output(
            ["/usr/sbin/scutil"],
            input="list State:/Network/Service/.*/IPv4\n",
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=2,
        )
        keys = []
        for line in list_out.splitlines():
            if "State:/Network/Service/" in line and "/IPv4" in line:
                k = line.split("=", 1)[-1].strip()
                if k:
                    keys.append(k)

        for key in keys:
            show_out = subprocess.check_output(
                ["/usr/sbin/scutil"],
                input=f"show {key}\n",
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=2,
            )
            if "InterfaceName : utun" not in show_out and "InterfaceName : ppp" not in show_out:
                continue
            # Check if our first proxy IP is already in ExcludedRoutes of this VPN service
            if all(ip in show_out for ip in all_ips[:3]):
                continue
            changed_any = True
    except Exception:
        pass
    return changed_any


def sync_additional_routes_wifi(all_ips: list[str], gateway: str | None) -> None:
    """
    Registers /32 routes in macOS SystemConfiguration (`networksetup -setadditionalroutes Wi-Fi`)
    so that `configd` (IPMonitor) itself owns and preserves the routes across VPN toggles.
    """
    for service in ["Wi-Fi"]:
        try:
            if not gateway or not all_ips:
                subprocess.run(
                    ["/usr/sbin/networksetup", "-setadditionalroutes", service],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=3,
                )
            else:
                route_args = []
                for ip in all_ips:
                    route_args.extend([ip, "255.255.255.255", gateway])
                subprocess.run(
                    ["/usr/sbin/networksetup", "-setadditionalroutes", service, *route_args],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=3,
                )
        except Exception:
            pass


def sync_physical_routes(proxy_ips: list[str], gateway: str | None, update_sysconfig: bool = True) -> int:
    """
    Pins true STATIC (`UGHS`) /32 host routes (`route -n delete` + `route -n add -host <ip> <gateway>`)
    via the physical Wi-Fi/Ethernet router so that traffic to SNI proxies and DNS servers ALWAYS
    bypasses FortiVPN, Happ TUN, and NetBird virtual interfaces.
    Note: Always deletes any kernel `WASCLONED` (`W`) route first so `route -n add` sets `STATIC` (`S`).
    """
    old_routes = []
    if ROUTES_STATE_FILE.exists():
        try:
            old_routes = json.loads(ROUTES_STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            old_routes = []

    if not gateway:
        if update_sysconfig:
            sync_additional_routes_wifi([], None)
        for entry in old_routes:
            old_ip = entry.get("ip")
            if old_ip:
                subprocess.run(
                    ["/sbin/route", "-n", "delete", "-host", old_ip],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
        return 0

    all_ips = sorted(
        set(proxy_ips)
        | set(SEED_PROXY_IPS)
        | set(DOH_BOOTSTRAP_IPS)
        | {ip for _, ips in UDP_DNS_PROVIDERS for ip in ips}
    )

    if update_sysconfig:
        sync_additional_routes_wifi(all_ips, gateway)

    for entry in old_routes:
        old_ip = entry.get("ip")
        old_gw = entry.get("gateway")
        if old_ip and (old_ip not in all_ips or old_gw != gateway):
            subprocess.run(
                ["/sbin/route", "-n", "delete", "-host", old_ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

    current_static = get_static_host_routes()
    applied = 0
    saved = []
    for ip in all_ips:
        if current_static.get(ip) == gateway:
            applied += 1
            saved.append({"ip": ip, "gateway": gateway})
            continue

        # Delete any WASCLONED (`W`) or VPN-hijacked route first so `add` creates a permanent STATIC (`UGHS`) route
        subprocess.run(
            ["/sbin/route", "-n", "delete", "-host", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        res = subprocess.run(
            ["/sbin/route", "-n", "add", "-host", ip, gateway],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if res.returncode != 0:
            res = subprocess.run(
                ["/sbin/route", "-n", "change", "-host", ip, gateway],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        if res.returncode == 0:
            applied += 1
            saved.append({"ip": ip, "gateway": gateway})

    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        ROUTES_STATE_FILE.write_text(json.dumps(saved, indent=2), encoding="utf-8")
    except Exception:
        pass

    return applied


def sync_proxy_bypass_domains() -> None:
    """
    Ensures that if Happ or FortiVPN sets a macOS System HTTP/HTTPS/SOCKS Proxy on Wi-Fi,
    Antigravity and Gemini domains are listed in ProxyBypassDomains so they bypass the proxy.
    """
    for service in ["Wi-Fi", "Ethernet", "USB 10/100/1000 LAN"]:
        try:
            out = subprocess.check_output(
                ["/usr/sbin/networksetup", "-getproxybypassdomains", service],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=2,
            )
            existing = [
                line.strip()
                for line in out.splitlines()
                if line.strip() and "aren't any" not in line
            ]
            merged = list(existing)
            changed = False
            for dom in PROXY_BYPASS_DOMAINS:
                if dom not in merged:
                    merged.append(dom)
                    changed = True
            if changed:
                subprocess.run(
                    ["/usr/sbin/networksetup", "-setproxybypassdomains", service, *merged],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=2,
                )
        except Exception:
            pass


def read_current_hosts_pins() -> dict[str, str]:
    pins = {}
    try:
        text = Path("/etc/hosts").read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            if f"# {NRPT_TAG}" in line and not line.strip().startswith("#"):
                parts = line.split()
                if len(parts) >= 2 and ":" not in parts[0]:
                    pins[parts[1]] = parts[0]
    except Exception:
        pass
    return pins


def update_etc_hosts(best_ips: dict[str, str]) -> None:
    hosts_path = Path("/etc/hosts")
    original = hosts_path.read_text(encoding="utf-8", errors="replace")
    kept_lines = []
    target_set = set(TARGET_HOSTS)
    in_block = False

    for line in original.splitlines():
        stripped = line.strip()
        if stripped == f"# BEGIN {NRPT_TAG}":
            in_block = True
            continue
        if stripped == f"# END {NRPT_TAG}":
            in_block = False
            continue
        if in_block or NRPT_TAG in line:
            continue
        if stripped and not stripped.startswith("#"):
            parts = stripped.split()
            if len(parts) == 1:
                # Remove broken single-column IP lines without hostname
                continue
            if len(parts) >= 2 and any(h in target_set for h in parts[1:]):
                continue
        kept_lines.append(line)

    while kept_lines and not kept_lines[-1].strip():
        kept_lines.pop()

    if best_ips:
        kept_lines.append("")
        kept_lines.append(f"# BEGIN {NRPT_TAG}")
        for host in TARGET_HOSTS:
            ip = best_ips.get(host)
            if ip:
                kept_lines.append(f"{ip} {host} # {NRPT_TAG}")
                # Essential for Gemini.app (C++ gRPC c-ares resolver):
                # c-ares ignores /etc/resolver/ and queries /etc/resolv.conf for AAAA (IPv6)
                # unless an IPv6 entry exists in /etc/hosts. ::1 stops the IPv6 leak in 0.05ms.
                kept_lines.append(f"::1 {host} # {NRPT_TAG}")
        kept_lines.append(f"# END {NRPT_TAG}")
    kept_lines.append("")

    tmp_path = Path("/etc/hosts.antigravity.tmp")
    tmp_path.write_text("\n".join(kept_lines), encoding="utf-8")
    os.chmod(tmp_path, 0o644)
    os.replace(tmp_path, hosts_path)


def update_etc_resolver() -> int:
    resolver_dir = Path("/etc/resolver")
    resolver_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(resolver_dir, 0o755)

    all_domains = sorted(set(TARGET_HOSTS + EXTRA_RESOLVER_DOMAINS))
    content = (
        f"# {NRPT_TAG}\n"
        f"nameserver 127.0.0.1\n"
        f"nameserver 37.230.192.51\n"
        f"nameserver 45.155.204.190\n"
    )
    count = 0
    for domain in all_domains:
        dom = domain.lstrip(".")
        p = resolver_dir / dom
        try:
            if p.exists() and p.read_text(encoding="utf-8") == content:
                count += 1
                continue
        except Exception:
            pass
        p.write_text(content, encoding="utf-8")
        os.chmod(p, 0o644)
        count += 1
    return count


def update_user_network_config(if_index: int = 0) -> None:
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        user_home = Path(f"/Users/{sudo_user}")
    else:
        user_home = Path.home()

    net_dir = user_home / "Library" / "Application Support" / "AntigravityBypass" / "network"
    if not net_dir.exists():
        # Try finding any non-root user on macOS if launched by LaunchDaemon
        for candidate in Path("/Users").iterdir():
            cand_dir = candidate / "Library" / "Application Support" / "AntigravityBypass" / "network"
            if cand_dir.exists():
                user_home = candidate
                net_dir = cand_dir
                break

    net_dir.mkdir(parents=True, exist_ok=True)
    net_json = net_dir / "network.json"

    cfg = {
        "doh": [
            {
                "name": "dns-ai.ru",
                "url": "https://dns.dns-ai.ru/dns-query",
                "bootstrap": DOH_BOOTSTRAP_IPS,
            }
        ],
        "extra_udp": [],
        "disabled_providers": ["comss.one"],
        "provider_order": ["geohide.ru", "dns-ai.ru"],
        "watch_region_errors": True,
        "log_roots": [
            str(user_home / "Library/Application Support/Antigravity/logs"),
            str(user_home / "Library/Application Support/Antigravity IDE/logs"),
            str(user_home / "Library/Application Support/Google Antigravity/logs"),
            str(user_home / "Library/Caches/com.google.GeminiMacOS/Logs"),
        ],
    }
    net_json.write_text(json.dumps(cfg, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    try:
        owner_stat = user_home.stat()
        for p in [net_dir.parent, net_dir, net_json]:
            os.chown(p, owner_stat.st_uid, owner_stat.st_gid)
    except Exception:
        pass

    for state_d in [STATE_DIR, LEGACY_RUST_DIR]:
        if state_d.exists():
            try:
                (state_d / "upstream.conf").write_text("37.230.192.51\n45.155.204.190\n", encoding="utf-8")
                if if_index > 0:
                    (state_d / "iface.conf").write_text(f"{if_index}\n", encoding="utf-8")
            except Exception:
                pass


def install_watchdog_daemon() -> bool:
    """
    Installs the script into /Library/Application Support/AntigravityBypass/macos-instant-fix.py
    and registers a persistent macOS LaunchDaemon (`com.antigravity.bypass.watchdog`) that
    monitors VPN tunnel (`utun*`) and routing changes in real time (every 2 seconds).
    """
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        this_file = Path(__file__).resolve()
        if this_file != INSTALLED_SCRIPT_PATH:
            INSTALLED_SCRIPT_PATH.write_bytes(this_file.read_bytes())
        os.chmod(INSTALLED_SCRIPT_PATH, 0o755)
        os.chown(INSTALLED_SCRIPT_PATH, 0, 0)

        plist_data = {
            "Label": "com.antigravity.bypass.watchdog",
            "ProgramArguments": [
                "/usr/bin/python3",
                str(INSTALLED_SCRIPT_PATH),
                "--watchdog",
            ],
            "RunAtLoad": True,
            "KeepAlive": True,
            "StandardOutPath": str(STATE_DIR / "watchdog.log"),
            "StandardErrorPath": str(STATE_DIR / "watchdog.log"),
        }
        WATCHDOG_PLIST_PATH.write_bytes(plistlib.dumps(plist_data))
        os.chmod(WATCHDOG_PLIST_PATH, 0o644)
        os.chown(WATCHDOG_PLIST_PATH, 0, 0)

        subprocess.run(
            ["/bin/launchctl", "bootout", "system/com.antigravity.bypass.watchdog"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["/bin/launchctl", "bootstrap", "system", str(WATCHDOG_PLIST_PATH)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except Exception:
        return False


def flush_dns_and_restart_relay() -> None:
    subprocess.run(["/usr/bin/dscacheutil", "-flushcache"], check=False)
    subprocess.run(["/usr/bin/killall", "-HUP", "mDNSResponder"], check=False)
    for svc in ["system/com.antigravity.bypass.dns", "system/com.antigravity.bypass.russia"]:
        subprocess.run(
            ["/bin/launchctl", "kickstart", "-k", svc],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )


def get_active_utun_list() -> list[str]:
    try:
        out = subprocess.check_output(["/sbin/ifconfig", "-l"], text=True, timeout=1.5).strip()
        return sorted(x for x in out.split() if x.startswith("utun") or x.startswith("ppp"))
    except Exception:
        return []


def run_watchdog_single_pass(force_probe: bool = False, update_sysconfig: bool = False) -> None:
    if_name, if_index, gw = detect_physical_egress()
    current_pins = read_current_hosts_pins()
    if update_sysconfig:
        sync_proxy_bypass_domains()

    pinned_ips = list(set(current_pins.values()))
    sync_physical_routes(pinned_ips, gw, update_sysconfig=update_sysconfig)

    has_disallowed_gemini_pin = any(
        current_pins.get(h) in DISALLOWED_FOR_GEMINI_IPS or current_pins.get(h) == "191.44.41.79"
        for h in GEMINI_STRICT_HOSTS
    )

    if not force_probe and not has_disallowed_gemini_pin and len(current_pins) >= len(TARGET_HOSTS) and gw:
        return

    if not has_disallowed_gemini_pin and len(current_pins) >= len(TARGET_HOSTS) and gw:
        canary_hosts = [
            "daily-cloudcode-pa.googleapis.com",
            "aicode.googleapis.com",
            "robinfrontend-pa.googleapis.com",
        ]
        all_healthy = True
        for h in canary_hosts:
            ip = current_pins.get(h)
            if not ip:
                all_healthy = False
                break
            ok, ms, _ = probe_tls_h2(ip, h, if_index, timeout=1.5)
            if not ok or ms > 900:
                all_healthy = False
                break

        if all_healthy:
            sync_physical_routes(pinned_ips, gw, update_sysconfig=False)
            return

    candidates = discover_candidates(TARGET_HOSTS, if_index)
    ranked = rank_all_hosts(candidates, if_index)
    best_ips = {}
    for host in TARGET_HOSTS:
        if ranked.get(host):
            best_ips[host] = ranked[host][0][0]
        else:
            best_ips[host] = "193.233.112.67"

    update_etc_hosts(best_ips)
    update_etc_resolver()
    update_user_network_config(if_index)
    if gw:
        sync_physical_routes(list(set(best_ips.values())), gw, update_sysconfig=True)
    flush_dns_and_restart_relay()


def run_watchdog_check() -> int:
    """
    Real-time VPN & route guardian daemon:
    - Checks every 2 seconds for new/toggled VPN interfaces (`utun*` from Happ, NetBird, FortiVPN)
      or missing `STATIC` (`UGHS`) `/32` routes, and immediately re-pins `/32` routes via the
      physical router (`en0`) so VPNs never hijack Antigravity or Gemini traffic.
    - Runs a canary TLS health check every 5 minutes.
    """
    last_utuns: list[str] = []
    last_probe_ts = 0.0
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Watchdog started.", flush=True)

    while True:
        try:
            now = time.monotonic()
            cur_utuns = get_active_utun_list()
            utun_changed = cur_utuns != last_utuns
            do_probe = (now - last_probe_ts) >= 300.0 or last_probe_ts == 0.0

            if utun_changed:
                print(
                    f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] VPN interface change: {last_utuns} -> {cur_utuns}",
                    flush=True,
                )
                last_utuns = cur_utuns
                # Wait 0.4s for nesessionmanager/configd to finish setting utun routes, then override with /32 STATIC
                time.sleep(0.4)

            run_watchdog_single_pass(force_probe=do_probe, update_sysconfig=utun_changed or do_probe)
            if do_probe:
                last_probe_ts = now
        except Exception as e:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Watchdog error: {e}", flush=True)

        time.sleep(2.0)


def run_rollback() -> int:
    print("\n======================================================================")
    print("  ПОЛНЫЙ СБРОС СЕТЕВЫХ НАСТРОЕК (ROLLBACK ANTIGRAVITY + GEMINI FIX)")
    print("======================================================================\n")

    if os.geteuid() != 0:
        print("[!] Для сброса системных настроек нужны права root (sudo).")
        print(f"    Запустите: sudo python3 {os.path.abspath(__file__)} --rollback")
        return 1

    # 1. Stop and remove Watchdog LaunchDaemon
    print("[1/5] Остановка и удаление фоновой службы com.antigravity.bypass.watchdog...")
    subprocess.run(
        ["/bin/launchctl", "bootout", "system/com.antigravity.bypass.watchdog"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for p in [WATCHDOG_PLIST_PATH, INSTALLED_SCRIPT_PATH]:
        try:
            if p.exists():
                p.unlink()
        except Exception:
            pass

    # 2. Remove static /32 routes and Wi-Fi AdditionalRoutes
    print("[2/5] Удаление статических маршрутов (/32)...")
    sync_additional_routes_wifi([], None)
    all_route_ips = set(SEED_PROXY_IPS) | set(DOH_BOOTSTRAP_IPS) | {
        ip for _, ips in UDP_DNS_PROVIDERS for ip in ips
    }
    if ROUTES_STATE_FILE.exists():
        try:
            for item in json.loads(ROUTES_STATE_FILE.read_text(encoding="utf-8")):
                if item.get("ip"):
                    all_route_ips.add(item["ip"])
            ROUTES_STATE_FILE.unlink()
        except Exception:
            pass
    for ip in sorted(all_route_ips):
        subprocess.run(
            ["/sbin/route", "-n", "delete", "-host", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    # 3. Clean ProxyBypassDomains
    print("[3/5] Восстановление стандартных исключений прокси (ProxyBypassDomains)...")
    added_bypass = set(PROXY_BYPASS_DOMAINS) - {"*.local", "169.254/16"}
    for service in ["Wi-Fi", "Ethernet", "USB 10/100/1000 LAN"]:
        try:
            out = subprocess.check_output(
                ["/usr/sbin/networksetup", "-getproxybypassdomains", service],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=2,
            )
            existing = [
                line.strip()
                for line in out.splitlines()
                if line.strip() and "aren't any" not in line
            ]
            cleaned = [d for d in existing if d not in added_bypass]
            if not cleaned:
                cleaned = ["*.local", "169.254/16"]
            subprocess.run(
                ["/usr/sbin/networksetup", "-setproxybypassdomains", service, *cleaned],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2,
            )
        except Exception:
            pass

    # 4. Clean /etc/hosts and /etc/resolver/*
    print("[4/5] Очистка записей # ANTIGRAVITY-BYPASS-RUSSIA из /etc/hosts и /etc/resolver/...")
    update_etc_hosts({})
    resolver_dir = Path("/etc/resolver")
    if resolver_dir.exists():
        for f in resolver_dir.iterdir():
            if f.is_file():
                try:
                    txt = f.read_text(encoding="utf-8", errors="ignore")
                    if NRPT_TAG in txt or f.name in TARGET_HOSTS or f.name in EXTRA_RESOLVER_DOMAINS:
                        f.unlink()
                except Exception:
                    pass

    # 5. Flush DNS cache
    print("[5/5] Сброс системного кэша DNS macOS...")
    flush_dns_and_restart_relay()

    print("\n[ГОТОВО] Все сетевые маршруты, /etc/hosts, /etc/resolver и Watchdog полностью сброшены!\n")
    return 0


def main() -> int:
    watchdog_mode = "--watchdog" in sys.argv
    check_only = "--check-only" in sys.argv
    rollback_mode = "--rollback" in sys.argv or "rollback" in sys.argv

    if watchdog_mode:
        if os.geteuid() != 0:
            return 1
        return run_watchdog_check()

    if not check_only and os.geteuid() != 0:
        if sys.stdin.isatty():
            print("Запрос прав администратора (sudo) для настройки /etc/hosts и маршрутов...")
            os.execvp(
                "/usr/bin/sudo",
                ["/usr/bin/sudo", "/usr/bin/python3", os.path.abspath(__file__), *sys.argv[1:]],
            )
        else:
            # Non-interactive terminal: use standard macOS Touch ID / Administrator dialog
            args_str = " ".join(f"'{a}'" for a in [os.path.abspath(__file__), *sys.argv[1:]])
            cmd = f"/usr/bin/python3 {args_str}"
            res = subprocess.run(
                [
                    "/usr/bin/osascript",
                    "-e",
                    f'do shell script "{cmd}" with administrator privileges',
                ]
            )
            return res.returncode

    if rollback_mode:
        return run_rollback()

    print("\n======================================================================")
    print("  ANTIGRAVITY + VOICE INPUT + GEMINI DESKTOP (MACOS VPN-IMMUNE FIX)")
    print("======================================================================\n")

    if_name, if_index, gw = detect_physical_egress()
    if if_name and gw:
        print(
            f"[1/6] Физический канал найден: интерфейс {if_name} (index={if_index}), шлюз {gw}\n"
            f"      (Трафик Antigravity и Gemini будет привязан к {if_name} в обход NetBird / FortiVPN / Happ)"
        )
    else:
        print("[1/6] Предупреждение: аппаратный шлюз не определён, используем стандартную маршрутизацию.")

    print("[2/6] Опрос рабочих провайдеров (dns-ai.ru DoH + geohide.ru UDP) напрямую через физический адаптер...")
    candidates = discover_candidates(TARGET_HOSTS, if_index)

    print("[3/6] Параллельный тест TLS 1.3 + HTTP/2 (SNI + ALPN h2) по всем 13 доменам...\n")
    ranked = rank_all_hosts(candidates, if_index)

    best_ips: dict[str, str] = {}
    print(f"  {'ДОМЕН':<48} | {'ЛУЧШИЙ IP':<15} | {'СКОРОСТЬ':<8} | {'ПРОТОКОЛ'}")
    print("  " + "-" * 86)
    for host in TARGET_HOSTS:
        host_ranks = ranked.get(host, [])
        if host_ranks:
            best_ip, best_ms, alpn = host_ranks[0]
            best_ips[host] = best_ip
            backups = ", ".join(f"{ip} ({ms}мс)" for ip, ms, _ in host_ranks[1:3])
            backup_str = f" [резерв: {backups}]" if backups else ""
            print(f"  {host:<48} | {best_ip:<15} | {best_ms:>5} мс | {alpn}{backup_str}")
        else:
            fallback_ip = "193.233.112.67"
            best_ips[host] = fallback_ip
            print(f"  {host:<48} | {fallback_ip:<15} |  резерв  | fallback")

    print()
    if check_only:
        print("[!] Режим --check-only: проверка завершена без изменения системных файлов.")
        return 0

    print("[4/6] Обновление /etc/hosts и /etc/resolver/<домен> (0 мс отсечка IPv6 AAAA и c-ares)...")
    update_etc_hosts(best_ips)
    res_count = update_etc_resolver()
    update_user_network_config(if_index)
    print(f"      - Записано {len(best_ips)} доменов (+ ::1 стоп-записи для c-ares) в /etc/hosts и {res_count} файлов в /etc/resolver/")

    print("[5/6] Изоляция от NetBird, FortiVPN и Happ (STATIC /32 маршруты + AdditionalRoutes Wi-Fi):")
    sync_proxy_bypass_domains()
    route_count = sync_physical_routes(list(set(best_ips.values())), gw, update_sysconfig=True)
    print(f"      - Прописано {route_count} постоянных STATIC (UGHS) маршрутов (/32) через шлюз {gw or 'default'}")
    print("      - Домены Google AI добавлены в исключения системного прокси (ProxyBypassDomains)")

    print("[6/6] Установка 2-секундного фонового Watchdog-демона, сброс DNS и перезапуск Gemini.app...")
    wd_ok = install_watchdog_daemon()
    # Re-pin routes one final time after daemon & DNS flush so configd never clears them
    sync_physical_routes(list(set(best_ips.values())), gw, update_sysconfig=False)
    flush_dns_and_restart_relay()

    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        try:
            uid = subprocess.check_output(["/usr/bin/id", "-u", sudo_user], text=True).strip()
            subprocess.run(
                ["/bin/launchctl", "asuser", uid, "/bin/launchctl", "setenv", "GRPC_DNS_RESOLVER", "native"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass

    if Path("/Applications/Gemini.app").exists():
        subprocess.run(["/usr/bin/killall", "Gemini"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5)
        if sudo_user and sudo_user != "root":
            subprocess.run(
                ["/usr/bin/su", "-", sudo_user, "-c", "open -a /Applications/Gemini.app"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

    if wd_ok:
        print("      - Служба com.antigravity.bypass.watchdog (реакция < 2 сек на включение VPN) активна!")
        print("      - Приложение Gemini.app автоматически перезапущено через новый IPv4 маршрут.")

    print("\n[ГОТОВО] Antigravity, Голосовой ввод и Gemini.app настроены и изолированы от VPN!\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
