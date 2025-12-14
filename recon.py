#!/usr/bin/env python3
#A python tool for TCP scanning, HTTP probing and TLS analysis

#Python libraries implemneted
import argparse
import socket
import time
from datetime import datetime, timezone
import json
import ssl
import re
import csv

#This sectionn is argument parsing
def parse_args():
    parser = argparse.ArgumentParser(
        description="Example argparse parser for network scanning flags"
    )
    # File containing one target per line
    parser.add_argument(
        "--targets",
        required=True,
        help="Path to file (one host per line; allow host or host:port)",
    )
    #Ports to scan  
    parser.add_argument(
        "--ports",
        required=True,
        help="Comma list or ranges (e.g., 80,443,8000-8100)",
    )
    #Number of concurent workers
    parser.add_argument(
        "--workers",
        type=int,
        default=20,
        help="Concurrent TCP workers (default 20)",
    )
    #Enable HTTP probing
    parser.add_argument(
        "--http",
        action="store_true",
        help="Probe HTTP(S) services and extract title, meta description, Server header",
    )
     #Enable TLS certificate analysis
    parser.add_argument(
        "--tls",
        action="store_true",
        help="Attempt TLS retrieval for ports that speak TLS",
    )
    #Output file prefix
    parser.add_argument(
        "--output",
        default="",
        help="Path prefix for results; tool writes PREFIX.results.json and PREFIX.results.csv",
    )
      #Timeout value for network connections
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Per-connection timeout in seconds (float OK)",
    )

    return parser.parse_args()        
#This section is helper functions
def parse_ports(port_string):

    #Converts a comma separated list or range of ports into a sorted list of integers
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
    #Load targets from a file and each non empty line is treated as a host
        with open(path) as f:
            return [line.strip() for line in f if line.strip()]


#This section is tcp connect
def tcp_connect(host, port, timeout):

    # Performs a TCP connect scan against a single host and port and returns open, closed or filtered status
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return "open"
    except ConnectionRefusedError: 
        return "closed"
    except:
        return "filtered"

#This section is banner grabbing
def get_banner(host, port, timeout):

    #This cdode attempts to read an initial banner from an open TCP service and reads up to 4096 bytes
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

#This section is http probing
def http_probe(host, port, timeout):

    #Performs a simple HTTP GET request on the given host and port and extracts title, meta description, and Server header
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
    # This code extracts server header
    match = re.search(r"Server:\s*(.+)\r\n", text, re.IGNORECASE)
    server_header = match.group(1).strip() if match else None
    #Extracts meta description
    match = re.search(r'<meta\s+name=["\']description["\']\s+content=["\'](.*?)["\']', text, re.IGNORECASE)
    meta_description = match.group(1).strip() if match else None
    # This code Ectracts title
    match = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
    title = match.group(1).strip() if match else None

    #This code returns the all inforamtion 
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

#This sectiob is TlS certifacte analysis
def https_probe(host, port, timeout):

    # This code Establsihes a TLS connection and extracts certifacte infomration
    try:
        ctx = ssl.create_default_context()
        raw = socket.create_connection((host, port), timeout)
        s = ctx.wrap_socket(raw, server_hostname=host)
        
        cert = s.getpeercert()
        s.close()
        # This code Extracts subject common name
        subject = dict(x[0] for x in cert.get("subject", [])) if cert else {}
        cn = subject.get("commonName")

        not_after = cert.get("notAfter") 
        expired = False
    # This code Checks if certifaicate is expired
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                exp = exp.replace(tzinfo=timezone.utc)
                expired = exp < datetime.now(timezone.utc)
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

#This section is scan port 
def scan_port(host, port, timeout, do_http, do_tls, retries):

    #This code scans a single port and performs HTTTP probing or TlS analysis
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

#This section is csv output
def save_csv(results, prefix):

    #This code saves scan results to a csv file
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

    #This code is the entry point to the program, it handles argumnet parsing, scanning and output 
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

    #This code is report structure
    results = {
        "meta": {
            "run_started": datetime.now(timezone.utc).isoformat(),
            "args": vars(args),
            "resumed": False
        },
        "targets": {host: {"ports": {}} for host in targets}
    }

    #This code performs the scan
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

    #This code saves JSON output
    output_file = f"{args.output}results.json"
    with open(output_file, "w") as f:
            json.dump(results, f, indent=2)

    #This code saves csv output
    save_csv(results, args.output)

    print(f"\nResults saved to: {output_file}")
    print(f"CSV saved to: {args.output}results.csv")


if __name__ == "__main__":
    main()

