#!/usr/bin/env python3
import argparse
import time
from datetime import datetime, timezone
import json



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



def tcp_connect(host, port, timeout):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return "open"

    except ConnectionRefusedError: 
        return "closed"

def get_banner(host, port, timeout):
    try:
        s = socket.create_connection((host, port), timeout)
        data = s.recv(4096)
        s.close()
        if not data:
            return None
        return data.decode(errors="ignore")
    except:
        return None

def http_probe(host, port, timeout):
    url = f"http://{host}:{port}/"

    try:
        s = socket.create_connection((host, port), timeout)
        req = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        s.sendall(req.encode())
        raw = s.recv(65535)
        s.close()

        resp = raw.decode(errors="ignore")
    except:
        return None

    result = {
        "url": url,
        "final_url": url,
        "status_code": None,
        "title": None,
        "meta_description": None,
        "server_header": None,
        "cookies": [],
        "favicon_sha256": None
    }

def https_probe(host, port, timeout):
    try:
        ctx = ssl.create_default_context()
        raw = socket.create_connection((host, port), timeout)
        s = ctx.wrap_socket(raw, server_hostname=host)
        
        cert = s.getpeercert()

        subject = dict(x[0] for x in cert.get("subject", [])) if cert else {}
        cn = subject.get("commonName")
        not_after = cert.get("notAfter") if cert else None

        expired = False
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                expired = exp < datetime.utcnow()
            except:
                pass

        s.close()

        return {
            "subject_cn": cn,
            "notAfter": not_after,
            "expired": expired,
            "weak_params": []
        }

    except:
        return None


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
    print("Starting TCP Connect Scan...\n")

    results = {
        "meta": {
            "run_started": now_utc(),
            "args": vars(args),
            "resumed": False
        },
        "targets": {}
    }

    for host in targets:
        results["targets"][host] = {"ports": {}}
        print(f"--- {host} ---")

        for port in ports:
            status = tcp_connect(host, port, args.timeout)
            port_entry = {"status": status}

            if status == "open":
                banner = get_banner(host, port, args.timeout)
                port_entry["banner"] = banner
                if banner:
                    print(f"{host}:{port} -> {status} | Banner: {banner[:60]}...")
                else:
                    print(f"{host}:{port} -> {status} | Banner: None")
            else:
                print(f"{host}:{port} -> {status}")
            
            if args.http and port == 80:
                    port_entry["http"] = http_probe(host, port, args.timeout)

            if args.http and port == 443:
                    port_entry["tls"] = https_probe(host, port, args.timeout)


            results["targets"][host]["ports"][str(port)] = port_entry

    output_file = f"{args.output}results.json"
    with open(output_file, "w") as f:
            json.dump(results, f, indent=2)

    print(f"\nResults saved to: {output_file}")



if __name__ == "__main__":
    main()

