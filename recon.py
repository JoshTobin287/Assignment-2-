#!/usr/bin/env python3
import argparse
import socket
import time
import datetime
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
        help="Path prefix for results; tool writes PREFIX.results.json and PREFIX.results.csv",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Per-connection timeout in seconds (float OK)",
    )

    return parser.parse_args()        


def tcp_connect(host, port, timeout):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return "open"

    except ConnectionRefusedError: 
        return "closed"

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

    for host, override_port in targets:

        scan_ports = [override_port] if override_port else ports

        print(f"\n--- Scanning {host} ---")

        for port in scan_ports:
            status = tcp_connect(host, port, args.timeout)

            if status == "open":
                print(f"[OPEN]     {host}:{port}")

            elif status == "Closed":
                print(f"[Closed]     {host}:{port}")


if __name__ == "__main__":
    main()

