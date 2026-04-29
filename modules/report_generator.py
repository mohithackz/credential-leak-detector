#!/usr/bin/env python3
"""
Report Generator Module
Creates the final aggregated JSON report from all scan phases.
"""

import os
import json
from datetime import datetime

CRITICAL_SOURCES = {"cit0day.in", "collection-1", "collection-4-u", "exploit.in"}


def _calculate_threat_level(emails_found, sf_results, dd_results):
    """Determine overall threat level based on scan findings."""
    has_critical = any(r.get("is_critical") for r in sf_results)
    total_breaches = sum(r.get("breach_count", 0) for r in sf_results)
    total_darkweb = sum(r.get("hits_count", 0) for r in dd_results)

    if has_critical:
        return "CRITICAL"
    elif total_breaches > 0 or total_darkweb > 0:
        return "HIGH"
    elif emails_found > 0:
        return "MEDIUM"
    elif emails_found == 0:
        return "LOW"
    return "NONE"


def generate_report(domain, timestamp, queries, emails, sf_results, dd_results, base_dir, duration):
    """
    Generate the final aggregated JSON report.

    Args:
        domain: Target domain
        timestamp: Scan timestamp
        queries: List of queries used (emails or domain)
        emails: Original emails found by harvester
        sf_results: SpiderFoot organized results
        dd_results: Darkdump results
        base_dir: Output directory
        duration: Scan duration in seconds

    Returns:
        str: Path to the generated report file
    """
    # Build lookup maps
    sf_map = {r["query"]: r for r in sf_results}
    dd_map = {r["query"]: r for r in dd_results}

    # Build per-query results
    results = []
    all_breach_sources = []

    for q in queries:
        sf = sf_map.get(q, {})
        dd = dd_map.get(q, {})

        breaches = sf.get("breaches", [])
        is_critical = sf.get("is_critical", False)
        darkweb_hits = dd.get("hits", [])

        all_breach_sources.extend(breaches)

        results.append({
            "email": q,
            "breaches": {
                "sources": breaches,
                "count": len(breaches),
                "is_critical": is_critical
            },
            "darkweb": {
                "mentions": darkweb_hits,
                "count": len(darkweb_hits)
            }
        })

    # Summary
    threat_level = _calculate_threat_level(len(emails), sf_results, dd_results)
    unique_sources = sorted(set(all_breach_sources))

    report = {
        "scan_info": {
            "tool": "Credential Leak Detector",
            "domain": domain,
            "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
            "scan_id": f"{domain}_{timestamp}",
            "duration_seconds": round(duration, 1),
        },
        "summary": {
            "emails_harvested": len(emails),
            "total_queries_scanned": len(queries),
            "breach_sources_found": len(unique_sources),
            "breach_sources_list": unique_sources,
            "darkweb_mentions": sum(r["darkweb"]["count"] for r in results),
            "threat_level": threat_level,
            "critical_breaches": any(r["breaches"]["is_critical"] for r in results),
        },
        "results": results
    }

    report_path = os.path.join(base_dir, f"report_{domain}_{timestamp}.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    return report_path
