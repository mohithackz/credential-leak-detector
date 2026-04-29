#!/bin/bash
# ============================================
# Credential Leak Detector - Setup Script
# One-command setup for fresh clone
# ============================================

set -e

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  Credential Leak Detector - Setup        ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# 1. Check Python 3
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[✗] Python3 is required but not installed.${NC}"
    echo "    Install: sudo apt install python3 python3-pip python3-venv"
    exit 1
fi
echo -e "${GREEN}[✔] Python3 found${NC}"

# 2. Create virtual environment
if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv venv
    echo -e "${GREEN}[✔] Virtual environment created${NC}"
else
    echo -e "${GREEN}[✔] Virtual environment exists${NC}"
fi

# Activate venv
source venv/bin/activate

# 3. Install Python dependencies
echo "[*] Installing Python dependencies..."
pip install -r requirements.txt --quiet
echo -e "${GREEN}[✔] Dependencies installed${NC}"

# 4. Clone Darkdump if not present
if [ ! -d "tools/darkdump" ]; then
    echo "[*] Cloning Darkdump into tools/darkdump..."
    mkdir -p tools
    git clone https://github.com/josh0xA/darkdump.git tools/darkdump --quiet
    if [ -f "tools/darkdump/requirements.txt" ]; then
        pip install -r tools/darkdump/requirements.txt --quiet
    fi
    echo -e "${GREEN}[✔] Darkdump installed${NC}"
else
    echo -e "${GREEN}[✔] Darkdump already present${NC}"
fi

# 5. Create output directory
mkdir -p output

# 6. Check for system tools
echo ""
echo "── System Tool Check ──"

if command -v theHarvester &> /dev/null; then
    echo -e "${GREEN}[✔] theHarvester found${NC}"
else
    echo -e "${YELLOW}[!] theHarvester not found${NC}"
    echo "    Install: sudo apt install theharvester"
    echo "         OR: pip3 install theHarvester"
fi

if command -v spiderfoot &> /dev/null || command -v sf &> /dev/null; then
    echo -e "${GREEN}[✔] SpiderFoot found${NC}"
else
    echo -e "${YELLOW}[!] SpiderFoot not found${NC}"
    echo "    Install: pip3 install spiderfoot"
fi

if command -v tor &> /dev/null; then
    echo -e "${GREEN}[✔] Tor found${NC}"
else
    echo -e "${YELLOW}[!] Tor not found${NC}"
    echo "    Install: sudo apt install tor"
fi

echo ""
echo "══════════════════════════════════════════"
echo -e "${GREEN}  Setup complete!${NC}"
echo ""
echo "  Activate venv:  source venv/bin/activate"
echo "  Run the tool:   python3 main.py"
echo "══════════════════════════════════════════"
echo ""
