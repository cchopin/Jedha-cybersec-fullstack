#!/bin/bash

echo "======================================"
echo "  SSTI Exploitation Framework Setup  "
echo "======================================"
echo ""

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "[*] Python version: $python_version"

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv venv
    echo "[+] Virtual environment created"
else
    echo "[!] Virtual environment already exists"
fi

# Activate virtual environment
echo "[*] Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "[*] Upgrading pip..."
pip install --upgrade pip -q

# Install requirements
echo "[*] Installing dependencies..."
pip install -r requirements.txt -q

echo ""
echo "[+] Setup complete!"
echo ""
echo "To use the tool:"
echo "  1. source venv/bin/activate"
echo "  2. python3 ssti_exploit.py"
echo ""
