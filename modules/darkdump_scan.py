#!/usr/bin/env python3
"""
Darkdump Module
Searches the dark web for leaked credentials using Darkdump via Tor.
Gracefully skips if Tor is not running.
"""

import os
import re
import json
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed


def _strip_ansi(text):
    """Remove ANSI escape codes from terminal output."""
    return re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', text or "")


def _parse_darkdump_output(raw_output):
    """Parse raw darkdump output into structured results."""
    text = _strip_ansi(raw_output)
    if "Searching For:" in text:
        text = text.split("Searching For:", 1)[1]
    results = []
    matches = re.findall(
        r'Website:\s*(.*?)\n\s*Information:\s*(.*?)\n\s*\|\s*Onion Link:\s*(.*?)\n',
        text, re.DOTALL
    )
    for website, info, onion in matches:
        results.append({
            "website": website.strip(),
            "information": info.strip(),
            "onion_link": onion.strip()
        })
    return results


def _scan_single(darkdump_path, query):
    """Run darkdump for a single query."""
    cmd = ["python3", darkdump_path, "-q", query, "-a", "10", "-s", "-p"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
        hits = _parse_darkdump_output(result.stdout + result.stderr)
        return {"query": query, "hits": hits, "hits_count": len(hits)}
    except subprocess.TimeoutExpired:
        return {"query": query, "hits": [], "hits_count": 0, "note": "timeout"}
    except Exception as e:
        return {"query": query, "hits": [], "hits_count": 0, "note": str(e)}


def _save_results(dd_dir, results):
    """Save darkdump results to JSON."""
    with open(os.path.join(dd_dir, "dd_clean.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)


def run_darkdump(domain, timestamp, queries, base_dir, env_status):
    """
    Run dark web investigation on all queries via Darkdump + Tor.
    Skips gracefully if Tor or Darkdump is unavailable.
    """
    dd_dir = os.path.join(base_dir, "Darkdump")
    os.makedirs(dd_dir, exist_ok=True)

    if not env_status.get("darkdump"):
        print("\033[93m[⚠] Darkdump not available — skipping Phase 3.\033[0m")
        placeholder = [{"query": q, "hits": [], "hits_count": 0} for q in queries]
        _save_results(dd_dir, placeholder)
        return placeholder

    if not env_status.get("tor"):
        print("\033[93m[⚠] Tor is not running — dark web scan skipped.\033[0m")
        print("     Start Tor with: sudo service tor start")
        placeholder = [{"query": q, "hits": [], "hits_count": 0} for q in queries]
        _save_results(dd_dir, placeholder)
        return placeholder

    darkdump_path = env_status["darkdump_path"]
    print(f"     Targets: {len(queries)} query(ies)")
    print(f"     Routing: via Tor SOCKS5 (127.0.0.1:9050)\n")

    dd_results = []
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {}
        for q in queries:
            print(f"\033[36m[⏳] Dark web search: {q}\033[0m")
            futures[executor.submit(_scan_single, darkdump_path, q)] = q
        for future in as_completed(futures):
            try:
                result = future.result()
                dd_results.append(result)
                if result["hits_count"] > 0:
                    print(f"\033[32m[✔] {result['query']}: {result['hits_count']} mention(s)\033[0m")
                else:
                    print(f"\033[90m[·] {result['query']}: no mentions\033[0m")
            except Exception:
                pass

    _save_results(dd_dir, dd_results)
    total = sum(r["hits_count"] for r in dd_results)
    if total > 0:
        print(f"\n\033[32m[✔] Darkdump found {total} dark web mention(s)\033[0m")
    else:
        print(f"\n\033[93m[!] No dark web mentions found.\033[0m")
    return dd_results
