#!/usr/bin/env python3
"""
Credential Leak Detector
Automated OSINT Pipeline for Domain Reconnaissance

Usage:
    python3 main.py                  # Interactive — asks for domain
    python3 main.py example.com      # Direct — scans immediately

Pipeline:
    Phase 1: Email Harvesting (theHarvester)
    Phase 2: Breach Detection (SpiderFoot)
    Phase 3: Dark Web Investigation (Darkdump + Tor)
    Output:  Aggregated JSON Report
"""

import os
import sys
import time
import json
import socket
from datetime import datetime

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from modules.env_check import check_environment
from modules.harvester import run_harvester
from modules.spiderfoot_scan import run_spiderfoot
from modules.darkdump_scan import run_darkdump
from modules.report_generator import generate_report


# ======================== UI Helpers ========================

def print_banner():
    """Print the tool banner."""
    banner = """
\033[96m╔══════════════════════════════════════════════════════╗
║                                                      ║
║   ░█▀▀ ░█▀▀█ ░█▀▀▀ ░█▀▀▄   ░█─── ░█▀▀▀ ░█▀▀█ ░█─▄▀ ║
║   ░█── ░█▄▄▀ ░█▀▀▀ ░█─░█   ░█─── ░█▀▀▀ ░█▄▄█ ░█▀▄─ ║
║   ░█▄▄ ░█─░█ ░█▄▄▄ ░█▄▄▀   ░█▄▄█ ░█▄▄▄ ░█─░█ ░█─░█ ║
║                                                      ║
║   ░█▀▀▄ ░█▀▀▀ ▀▀█▀▀ ░█▀▀▀ ░█▀▀█ ▀▀█▀▀ ░█▀▀▀█ ░█▀▀█ ║
║   ░█─░█ ░█▀▀▀ ─░█── ░█▀▀▀ ░█─── ─░█── ░█──░█ ░█▄▄▀ ║
║   ░█▄▄▀ ░█▄▄▄ ─░█── ░█▄▄▄ ░█▄▄█ ─░█── ░█▄▄▄█ ░█─░█ ║
║                                                      ║
║           Automated OSINT Pipeline                   ║
║     github.com/YOUR_USERNAME/credential-leak-detector║
╚══════════════════════════════════════════════════════╝\033[0m
"""
    print(banner)


def print_phase_header(phase_num, title, tool_name):
    """Print a phase separator."""
    print(f"\n\033[97m{'═' * 55}")
    print(f"  [Phase {phase_num}] {title}")
    print(f"  Tool: {tool_name}")
    print(f"{'═' * 55}\033[0m\n")


def print_summary(report_path, report_data):
    """Print the final scan summary."""
    s = report_data["summary"]
    info = report_data["scan_info"]

    print(f"\n\033[97m{'═' * 55}")
    print(f"  ✔  SCAN COMPLETE")
    print(f"{'═' * 55}\033[0m\n")

    print(f"  📁 Report:    {report_path}")
    print(f"  🕐 Duration:  {info['duration_seconds']}s")
    print(f"  📧 Emails:    {s['emails_harvested']}")
    print(f"  🔓 Breaches:  {s['breach_sources_found']} source(s)")
    print(f"  🌐 Dark Web:  {s['darkweb_mentions']} mention(s)")

    # Threat level with color
    level = s["threat_level"]
    colors = {
        "CRITICAL": "\033[91m",  # Red
        "HIGH": "\033[91m",      # Red
        "MEDIUM": "\033[93m",    # Yellow
        "LOW": "\033[32m",       # Green
        "NONE": "\033[90m",      # Gray
    }
    color = colors.get(level, "\033[0m")
    print(f"  ⚠️  Threat:    {color}{level}\033[0m")

    if s.get("critical_breaches"):
        print(f"\n  \033[91m🚨 CRITICAL: Credentials found in known breach databases!\033[0m")

    print()


def validate_domain(domain):
    """Validate that the domain is resolvable."""
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        print(f"\033[91m[✗] Cannot resolve domain: {domain}\033[0m")
        print(f"    Make sure the domain is correct and you have internet access.")
        return False


# ======================== Main Pipeline ========================

def main():
    print_banner()

    # Step 1: Environment check (silent if all good)
    env_status = check_environment()

    # Step 2: Get target domain
    if len(sys.argv) > 1:
        domain = sys.argv[1].strip()
    else:
        domain = input("\033[97m  Enter target domain: \033[0m").strip()

    if not domain:
        print("\033[91m[✗] No domain provided.\033[0m")
        sys.exit(1)

    if not validate_domain(domain):
        sys.exit(1)

    # Step 3: Setup output directory
    timestamp = datetime.now().strftime("%H%M_%d%m")
    base_dir = os.path.join(PROJECT_ROOT, "output", f"{domain}_{timestamp}")
    os.makedirs(base_dir, exist_ok=True)

    print(f"\n\033[97m  Target:  {domain}")
    print(f"  Output:  {base_dir}\033[0m")

    start_time = time.time()

    # ════════════════════════════════════════════
    # Phase 1: Email Harvesting
    # ════════════════════════════════════════════
    print_phase_header(1, "Email Harvesting", "theHarvester")
    emails = run_harvester(domain, base_dir)

    # If no emails found, continue with domain-level query
    queries = emails if emails else [domain]

    # ════════════════════════════════════════════
    # Phase 2: Breach Detection
    # ════════════════════════════════════════════
    print_phase_header(2, "Breach Detection", "SpiderFoot")
    sf_results = run_spiderfoot(domain, timestamp, queries, base_dir, env_status)

    # ════════════════════════════════════════════
    # Phase 3: Dark Web Investigation
    # ════════════════════════════════════════════
    print_phase_header(3, "Dark Web Investigation", "Darkdump + Tor")
    dd_results = run_darkdump(domain, timestamp, queries, base_dir, env_status)

    # ════════════════════════════════════════════
    # Generate Report
    # ════════════════════════════════════════════
    duration = time.time() - start_time
    report_path = generate_report(
        domain, timestamp, queries, emails,
        sf_results, dd_results, base_dir, duration
    )

    # Load and display summary
    with open(report_path, "r") as f:
        report_data = json.load(f)

    print_summary(report_path, report_data)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\033[93m[!] Scan interrupted by user.\033[0m")
        sys.exit(0)
