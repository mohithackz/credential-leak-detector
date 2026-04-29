#!/usr/bin/env python3
"""
Environment Checker Module
Silently validates that all required OSINT tools are installed.
Shows install instructions ONLY if something is missing.
"""

import os
import sys
import shutil
import socket
import subprocess
import time


# ======================== Path Detection ========================

def get_project_root():
    """Returns absolute path to the project root directory."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_darkdump_path():
    """Returns the expected path for darkdump inside the project."""
    return os.path.join(get_project_root(), "tools", "darkdump", "darkdump.py")


# ======================== Tool Checks ========================

def is_theharvester_installed():
    """Check if theHarvester is available in PATH."""
    return shutil.which("theHarvester") is not None


def is_spiderfoot_installed():
    """Check if SpiderFoot CLI is available (sf or spiderfoot command)."""
    return shutil.which("spiderfoot") is not None or shutil.which("sf") is not None


def get_spiderfoot_cmd():
    """Returns the correct SpiderFoot command name."""
    if shutil.which("spiderfoot"):
        return "spiderfoot"
    elif shutil.which("sf"):
        return "sf"
    return None


def is_darkdump_installed():
    """Check if darkdump exists inside the project's tools/ directory."""
    return os.path.exists(get_darkdump_path())


def is_tor_running(host="127.0.0.1", port=9050, timeout=3):
    """Check if Tor SOCKS proxy is accessible."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, ConnectionRefusedError):
        return False


def wait_for_tor(host="127.0.0.1", port=9050, timeout=30):
    """Wait for Tor SOCKS proxy to become available."""
    start = time.time()
    while time.time() - start < timeout:
        if is_tor_running(host, port):
            return True
        time.sleep(1)
    return False


def try_start_tor():
    """Attempt to start Tor service."""
    try:
        result = subprocess.run(["pgrep", "tor"], capture_output=True)
        if result.returncode == 0:
            return wait_for_tor()
        subprocess.Popen(["tor"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return wait_for_tor()
    except Exception:
        return False


# ======================== Main Check ========================

def check_environment():
    """
    Validates that all required tools are installed.
    
    - If everything is fine → returns silently (no output at all)
    - If tools are missing → prints what's missing with install commands → exits
    - If Tor is down → warns but continues (Darkdump will be skipped)
    
    Returns:
        dict: Status of each tool + tor availability
    """
    missing = []
    warnings = []
    status = {
        "theharvester": False,
        "spiderfoot": False,
        "spiderfoot_cmd": None,
        "darkdump": False,
        "darkdump_path": get_darkdump_path(),
        "tor": False,
    }

    # Check theHarvester
    if is_theharvester_installed():
        status["theharvester"] = True
    else:
        missing.append(
            ("theHarvester", "sudo apt install theharvester  OR  pip3 install theHarvester")
        )

    # Check SpiderFoot
    if is_spiderfoot_installed():
        status["spiderfoot"] = True
        status["spiderfoot_cmd"] = get_spiderfoot_cmd()
    else:
        missing.append(
            ("SpiderFoot", "pip3 install spiderfoot")
        )

    # Check Darkdump (inside project tools/)
    if is_darkdump_installed():
        status["darkdump"] = True
    else:
        missing.append(
            ("Darkdump", "git clone https://github.com/josh0xA/darkdump.git tools/darkdump\n"
             "             Then: pip3 install -r tools/darkdump/requirements.txt")
        )

    # Check Tor (warning only — not critical)
    if is_tor_running():
        status["tor"] = True
    else:
        # Try starting it
        if try_start_tor():
            status["tor"] = True
        else:
            warnings.append("Tor is not running. Dark web scan (Phase 3) will be skipped.")
            warnings.append("  → Start Tor: sudo service tor start")

    # === Output ===
    if missing:
        print("\n[!] Missing tools detected:\n")
        for tool, install_cmd in missing:
            print(f"    \033[91m✗\033[0m {tool} not found")
            print(f"      → Install: {install_cmd}\n")
        print("[!] Install the missing tools and re-run the script.")
        print("    Or run: ./setup.sh  (for automated setup)\n")
        sys.exit(1)

    # Print warnings (Tor only) — these don't block execution
    if warnings:
        for w in warnings:
            print(f"\033[93m[⚠] {w}\033[0m")
        print()

    return status
