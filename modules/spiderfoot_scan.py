#!/usr/bin/env python3
"""
SpiderFoot Module
Runs breach detection scans on discovered emails using SpiderFoot CLI.
Supports parallel scanning for efficiency.
"""

import os
import re
import json
import subprocess
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed


# Breach-focused SpiderFoot modules
EMAIL_MODULES = "sfp_citadel,sfp_breach,sfp_haveibeenpwned,sfp_leakix"

# Known critical breach databases
CRITICAL_SOURCES = {"cit0day.in", "collection-1", "collection-4-u", "exploit.in"}


def _get_sf_cmd(env_status):
    """Get the SpiderFoot command from env_check results."""
    cmd = env_status.get("spiderfoot_cmd")
    if cmd:
        return cmd
    # Fallback
    return "spiderfoot"


def _scan_single_query(sf_cmd, query, output_path):
    """Run SpiderFoot scan for a single query (email or domain)."""
    safe_name = re.sub(r'[^a-zA-Z0-9]', '_', query)
    command = [sf_cmd, "-s", query, "-o", "json", "-q", "-m", EMAIL_MODULES]

    try:
        print(f"\033[36m[⏳] SpiderFoot scanning: {query}\033[0m")
        with open(output_path, "w", encoding="utf-8") as fout:
            subprocess.run(
                command,
                stdout=fout,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300,
                check=False
            )
        time.sleep(2)  # Rate limiting between scans
        print(f"\033[32m[✔] Completed: {query}\033[0m")
    except subprocess.TimeoutExpired:
        print(f"\033[93m[⚠] Timeout: {query} (skipped after 5 min)\033[0m")
        with open(output_path, "w") as f:
            json.dump([], f)
    except Exception as e:
        print(f"\033[91m[✗] SpiderFoot error for {query}: {e}\033[0m")
        with open(output_path, "w") as f:
            json.dump([], f)


def _parse_sf_json(path):
    """Parse a SpiderFoot JSON output file."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, FileNotFoundError):
        return []


def _organize_results(all_items):
    """
    Organize raw SpiderFoot results into clean per-query structure.
    Extracts breach sources and categorizes findings.
    """
    by_query = defaultdict(lambda: {"breaches": [], "raw_types": []})

    for item in all_items:
        src = item.get("source") or item.get("src") or ""
        item_type = item.get("type", "")
        data = item.get("data", "")

        if src:
            by_query[src]["raw_types"].append(item_type)
            # Extract breach source name from data like "[cit0day.in]"
            breach_match = re.search(r'\[(.*?)\]', data)
            if breach_match:
                by_query[src]["breaches"].append(breach_match.group(1).strip())

    results = []
    for query, info in by_query.items():
        breaches = sorted(set(info["breaches"]))
        is_critical = bool(set(breaches) & CRITICAL_SOURCES)
        results.append({
            "query": query,
            "breaches": breaches,
            "breach_count": len(breaches),
            "is_critical": is_critical,
            "raw_types": sorted(set(info["raw_types"])),
        })

    # Sort: emails first, then alphabetical
    return sorted(results, key=lambda x: (0 if "@" in x["query"] else 1, x["query"]))


def run_spiderfoot(domain, timestamp, queries, base_dir, env_status):
    """
    Run SpiderFoot breach detection scans on all queries (emails/domain).
    
    Args:
        domain: Target domain
        timestamp: Scan timestamp string
        queries: List of emails or [domain] to scan
        base_dir: Output directory for this scan
        env_status: Result from env_check.check_environment()
        
    Returns:
        list: Organized scan results per query
    """
    if not env_status.get("spiderfoot"):
        print("\033[93m[⚠] SpiderFoot not available — skipping Phase 2.\033[0m")
        return []

    sf_cmd = _get_sf_cmd(env_status)
    sf_dir = os.path.join(base_dir, "SpiderFoot")
    os.makedirs(sf_dir, exist_ok=True)

    print(f"     Targets: {len(queries)} query(ies)")
    print(f"     Modules: {EMAIL_MODULES}\n")

    # Run scans in parallel (max 3 concurrent)
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {}
        for q in queries:
            safe_name = re.sub(r'[^a-zA-Z0-9]', '_', q)
            out_path = os.path.join(sf_dir, f"{safe_name}.json")
            futures[executor.submit(_scan_single_query, sf_cmd, q, out_path)] = q

        for future in as_completed(futures):
            try:
                future.result()
            except Exception:
                pass

    # Parse and organize all results
    all_items = []
    for q in queries:
        safe_name = re.sub(r'[^a-zA-Z0-9]', '_', q)
        path = os.path.join(sf_dir, f"{safe_name}.json")
        all_items.extend(_parse_sf_json(path))

    organized = _organize_results(all_items)

    # Save clean summary
    summary_path = os.path.join(sf_dir, "sf_clean.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(organized, f, indent=2)

    # Print summary
    total_breaches = sum(r["breach_count"] for r in organized)
    critical = any(r["is_critical"] for r in organized)

    if total_breaches > 0:
        print(f"\n\033[32m[✔] SpiderFoot found {total_breaches} breach source(s)\033[0m")
        if critical:
            print(f"\033[91m[🚨] CRITICAL breaches detected!\033[0m")
        for r in organized:
            if r["breaches"]:
                print(f"     {r['query']}: {', '.join(r['breaches'])}")
    else:
        print(f"\n\033[93m[!] No breach data found via SpiderFoot.\033[0m")

    return organized
