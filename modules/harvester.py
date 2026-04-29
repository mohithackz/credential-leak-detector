#!/usr/bin/env python3
"""
theHarvester Module
Runs passive OSINT email harvesting for a target domain.
Returns whatever it finds — no fake data injection.
"""

import os
import re
import subprocess


# Reliable passive sources that don't usually hang
HARVEST_SOURCES = "bing,duckduckgo,crtsh,virustotal"


def extract_emails_from_output(raw_text, domain):
    """Extract unique emails matching the target domain from raw output."""
    pattern = re.compile(
        r"[a-zA-Z0-9._%+\-]+@" + re.escape(domain),
        re.IGNORECASE
    )
    emails = sorted(set(pattern.findall(raw_text)))
    return emails


def run_harvester(domain, base_dir):
    """
    Run theHarvester against the target domain.
    
    Args:
        domain: Target domain (e.g., 'example.com')
        base_dir: Output directory for this scan
        
    Returns:
        list: Discovered email addresses (may be empty — that's honest)
    """
    harvest_dir = os.path.join(base_dir, "theHarvester")
    os.makedirs(harvest_dir, exist_ok=True)

    raw_file = os.path.join(harvest_dir, "raw_output.txt")
    clean_file = os.path.join(harvest_dir, "clean_emails.txt")

    cmd = [
        "theHarvester",
        "-d", domain,
        "-b", HARVEST_SOURCES,
        "-l", "500"
    ]

    print(f"\033[36m[⏳] Scanning {domain} across passive sources...\033[0m")
    print(f"     Sources: {HARVEST_SOURCES}")

    try:
        # Run with live output so the user sees progress
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        full_output = ""
        for line in process.stdout:
            print(f"     {line}", end="")
            full_output += line

        process.wait()

        # Save raw output
        with open(raw_file, "w", encoding="utf-8", errors="ignore") as f:
            f.write(full_output)

        # Extract emails
        emails = extract_emails_from_output(full_output, domain)

        # Save clean email list
        with open(clean_file, "w", encoding="utf-8") as f:
            for email in emails:
                f.write(email + "\n")

        if emails:
            print(f"\n\033[32m[✔] Found {len(emails)} unique email(s)\033[0m")
            for e in emails:
                print(f"     📧 {e}")
        else:
            print(f"\n\033[93m[!] No emails found via passive sources.\033[0m")
            print(f"     Pipeline will continue with domain-level scan.")

        return emails

    except FileNotFoundError:
        print("\033[91m[✗] theHarvester command not found.\033[0m")
        return []
    except Exception as e:
        print(f"\033[91m[✗] theHarvester error: {e}\033[0m")
        return []
