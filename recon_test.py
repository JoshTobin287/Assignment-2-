#!/usr/bin/env python3
import argparse
import socket
import time
from datetime import datetime, timezone
import json
import ssl
import re
import csv


def parse_args():
    parser = argparse.ArgumentParser(
        description="Example argparse parser for network scanning flags"
    )

    parser.add_argument(
        "--targets",
        required=True,
        help="Path to file (one host per line; allow host or host:port)",
    )

    parser.add_argument(
        "--ports",
        required=True,
        help="Comma list or ranges (e.g., 80,443,8000-8100)",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=20,
        help="Concurrent TCP workers (default 20)",
    )

    parser.add_argument(
        "--http",
        action="store_true",
        help="Probe HTTP(S) services and extract title, meta description, Server header",
    )

    parser.add_argument(
        "--tls",
        action="store_true",
        help="Attempt TLS retrieval for ports that speak TLS",
    )

    parser.add_argument(
        "--output",
        default="",
        help="Path prefix for results; tool writes PREFIX.results.json and PREFIX.results.csv",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Per-connection timeout in seconds (float OK)",
    )

    return parser.parse_args()        

def parse_ports(port_string):
    ports = set()
    for part in port_string.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end)+1))
        else:
            ports.add(int(part))
    return sorted(ports)

def load_targets(path):
        with open(path) as f:
            return [line.strip() for line in f if line.strip()]


#tcp connect
def tcp_connect(host, port, timeout):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return "open"
    except ConnectionRefusedError: 
        return "closed"
    except:
        return "filtered"

#banner
def get_banner(host, port, timeout):
    try:
        s = socket.create_connection((host, port), timeout)
        s.settimeout(2.0)

        try:
            data = s.recv(4096)
        except socket.timeout:
            date = b""
        s.close()

        return data.decode(errors="ignore") if data else None
    except:
        return None

#http
def http_probe(host, port, timeout):
    url = f"http://{host}:{port}/"

    try:
        s = socket.create_connection((host, port), timeout)
        req = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        s.sendall(req.encode())
        
        raw = b""
        while True:
            chunk = s.recv(65535)
            if not chunk:
                break
            raw += chunk
        s.close()

        text = raw.decode(errors="ignore")

    except:
        return None

    match = re.search(r"Server:\s*(.+)\r\n", text, re.IGNORECASE)
    server_header = match.group(1).strip() if match else None

    match = re.search(r'<meta\s+name=["\']description["\']\s+content=["\'](.*?)["\']', text, re.IGNORECASE)
    meta_description = match.group(1).strip() if match else None

    match = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
    title = match.group(1).strip() if match else None

    result = {
        "url": url,
        "final_url": url,
        "status_code": None,
        "title": title,
        "meta_description": meta_description,
        "server_header": server_header,
        "cookies": [],
        "favicon_sha256": None
    }
    return result

#https
def https_probe(host, port, timeout):
    try:
        ctx = ssl.create_default_context()
        raw = socket.create_connection((host, port), timeout)
        s = ctx.wrap_socket(raw, server_hostname=host)
        
        cert = s.getpeercert()
        s.close()

        subject = dict(x[0] for x in cert.get("subject", [])) if cert else {}
        cn = subject.get("commonName")

        not_after = cert.get("notAfter") 
        expired = False

        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                expired = exp < datetime.utcnow()
            except:
                expired = False

        return {
            "subject_cn": cn,
            "notAfter": not_after,
            "expired": expired,
            "weak_params": []
        }

    except:
        return None
def scan_port(host, port, timeout, do_http, do_tls, retries):

    for _ in range(retries + 1):
        status = tcp_connect(host, port, timeout)
        if status == "open":
            break
        time.sleep(0.1)

    entry = {"status": status}

    if status == "open":
        if do_http and port == 80:
            entry["http"] = http_probe(host, port, timeout)
            entry["banner"] = entry["http"]["server_header"]

        if do_tls and port == 443:
            entry["tls"] = https_probe(host, port, timeout)
            entry["banner"] = entry["tls"]["subject_cn"]
    return entry

def save_csv(results, prefix):
    with open(f"{prefix}results.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "host", "port", "status", "banner",
            "http_title", "http_server", "http_meta",
            "tls_cn", "tls_expired"
        ])

        for host, data in results["targets"].items():
            for port, pdata in data["ports"].items():
                writer.writerow([
                    host,
                    port,
                    pdata.get("status"),
                    (pdata.get("banner") or "")[:80],
                    (pdata.get("http") or {}).get("title"),
                    (pdata.get("http") or {}).get("server_header"),
                    (pdata.get("http") or {}).get("meta_description"),
                    (pdata.get("tls") or {}).get("subject_cn"),
                    (pdata.get("tls") or {}).get("expired"),
                ])


#main
def main():
    args = parse_args()
    print("Arguments Received:")
    print(f"  targets : {args.targets}")
    print(f"  ports   : {args.ports}")
    print(f"  workers : {args.workers}")
    print(f"  http    : {args.http}")
    print(f"  tls     : {args.tls}")
    print(f"  output  : {args.output}")
    print(f"  timeout : {args.timeout}")

    targets = load_targets(args.targets)
    ports = parse_ports(args.ports)

    print(f"\nLoaded {len(targets)} targets and {len(ports)} ports")
    print("TCP Connect Scan\n")

    results = {
        "meta": {
            "run_started": datetime.now(timezone.utc).isoformat(),
            "args": vars(args),
            "resumed": False
        },
        "targets": {host: {"ports": {}} for host in targets}
    }

    for host in targets:
        print(f"--- {host} ---")
        for port in ports:
            entry = scan_port(host, port, args.timeout, args.http, args.tls, retries=2)
            results["targets"][host]["ports"][str(port)] = entry

            if entry["status"] == "open":
                banner = entry.get("banner")
                bshort = banner[:60] + "..." if banner else "None"
                print(f"{host}:{port} -> open | Banner: {bshort}")
            else:
                print(f"{host}:{port} -> {entry['status']}")

    output_file = f"{args.output}results.json"
    with open(output_file, "w") as f:
            json.dump(results, f, indent=2)

    save_csv(results, args.output)

    print(f"\nResults saved to: {output_file}")
    print(f"CSV saved to: {args.output}results.csv")


if __name__ == "__main__":
    main()

