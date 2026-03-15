#!/bin/bash
# Auto Install Python Dependencies
# Cara pakai: bash -c "$(curl -fsSL https://raw.githubusercontent.com/USERNAME/REPO/main/install-python-deps.sh)"

# Warna untuk output (optional, fallback jika tidak ada color)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Deteksi OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        OS=$(uname -s)
    fi
    echo "$OS"
}

# Fungsi install package sesuai OS
install_system_packages() {
    local os=$1
    echo -e "${YELLOW}Detected OS: $os${NC}"
    
    case $os in
        ubuntu|debian)
            apt-get update -y
            apt-get install -y python3 python3-pip python3-venv build-essential libssl-dev libffi-dev python3-dev wget curl git
            ;;
        centos|rhel|fedora|almalinux)
            yum install -y epel-release
            yum install -y python3 python3-pip python3-devel gcc openssl-devel libffi-devel wget curl git
            ;;
        *)
            echo -e "${RED}Unsupported OS. Installing Python via package manager...${NC}"
            if command -v apt-get &>/dev/null; then
                apt-get update -y && apt-get install -y python3 python3-pip
            elif command -v yum &>/dev/null; then
                yum install -y python3 python3-pip
            else
                echo -e "${RED}Please install Python 3 manually${NC}"
                exit 1
            fi
            ;;
    esac
}

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}  Auto Install Python Dependencies${NC}"
echo -e "${BLUE}========================================${NC}"

# Deteksi OS
OS_TYPE=$(detect_os)

# Install system packages
echo -e "\n${YELLOW}[1] Installing system packages...${NC}"
install_system_packages "$OS_TYPE"

# Upgrade pip
echo -e "\n${YELLOW}[2] Upgrading pip...${NC}"
python3 -m pip install --upgrade pip setuptools wheel

# Install Python dependencies
echo -e "\n${YELLOW}[3] Installing Python dependencies...${NC}"

# Buat requirements sementara
cat > /tmp/python-deps.txt << 'EOF'
# Core dependencies
requests>=2.28.0
urllib3>=1.26.0

# Web scraping
beautifulsoup4>=4.12.0

# SSH/Network
paramiko>=3.0.0

# Utilities
colorama>=0.4.6

# Concurrent operations
futures>=3.0.0

# Parsing HTML/XML
lxml>=4.9.0

# Untuk logging dan warnings (built-in, tapi kita include)
# warnings sudah built-in

# Security
cryptography>=39.0.0
pyOpenSSL>=23.0.0

# Network tools
scapy>=2.5.0  # optional untuk network scanning
netifaces>=0.11.0

# Threading & concurrency
threading  # built-in
concurrent.futures  # built-in di Python 3.2+

# URL parsing
urllib.parse  # built-in

# Regex
re  # built-in

# System
os, sys, socket, datetime  # built-in
EOF

# Install dependencies
python3 -m pip install -r /tmp/python-deps.txt
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Python dependencies installed successfully${NC}"
else
    echo -e "${RED}✗ Failed to install some dependencies${NC}"
fi

# Install dependencies tambahan untuk networking
echo -e "\n${YELLOW}[4] Installing additional network tools...${NC}"
if command -v apt-get &>/dev/null; then
    apt-get install -y netcat nmap sshpass openssh-client net-tools dnsutils
elif command -v yum &>/dev/null; then
    yum install -y nc nmap sshpass openssh-clients net-tools bind-utils
fi

# Verifikasi instalasi
echo -e "\n${YELLOW}[5] Verifying installation...${NC}"
python3 -c "
import sys
dependencies = [
    ('requests', 'requests'),
    ('bs4', 'beautifulsoup4'),
    ('paramiko', 'paramiko'),
    ('colorama', 'colorama'),
    ('urllib3', 'urllib3'),
    ('lxml', 'lxml'),
    ('cryptography', 'cryptography'),
    ('OpenSSL', 'pyOpenSSL')
]

print('${BLUE}Testing imports:${NC}')
all_good = True
for module_name, package_name in dependencies:
    try:
        if module_name == 'bs4':
            import bs4
            module = bs4
        else:
            module = __import__(module_name)
        print(f'${GREEN}✓ {package_name} imported successfully${NC}')
    except ImportError as e:
        print(f'${RED}✗ {package_name} failed: {e}${NC}')
        all_good = False

# Test built-in modules
builtins = ['re', 'sys', 'os', 'socket', 'datetime', 'threading', 'concurrent.futures', 'urllib.parse']
for module in builtins:
    try:
        __import__(module)
        print(f'${GREEN}✓ {module} (built-in)${NC}')
    except ImportError:
        print(f'${RED}✗ {module} (built-in) not available${NC}')
        all_good = False

if all_good:
    print('${GREEN}✓ All dependencies verified!${NC}')
    sys.exit(0)
else:
    print('${RED}✗ Some dependencies are missing${NC}')
    sys.exit(1)
"

# Buat file requirements untuk referensi
cp /tmp/python-deps.txt ./requirements.txt
echo -e "\n${GREEN}✓ Requirements file saved to ./requirements.txt${NC}"

# Buat script tester sederhana
echo -e "\n${YELLOW}[6] Creating test script...${NC}"
cat > test_deps.py << 'EOF'
#!/usr/bin/env python3
"""
Test script untuk memverifikasi semua dependencies
"""
import sys
import os
import re
import socket
import time
import datetime
import threading
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

# Third party imports
try:
    import requests
    print("✓ requests")
except ImportError:
    print("✗ requests")

try:
    from bs4 import BeautifulSoup
    print("✓ beautifulsoup4")
except ImportError:
    print("✗ beautifulsoup4")

try:
    import paramiko
    print("✓ paramiko")
except ImportError:
    print("✗ paramiko")

try:
    from colorama import Fore, Style, init
    print("✓ colorama")
except ImportError:
    print("✗ colorama")

try:
    import urllib3
    print("✓ urllib3")
except ImportError:
    print("✗ urllib3")

print("\n✅ All tests completed!")
EOF

chmod +x test_deps.py
echo -e "${GREEN}✓ Test script created: ./test_deps.py${NC}"

# Tampilkan hasil
echo -e "\n${BLUE}========================================${NC}"
echo -e "${GREEN}Installation Complete!${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "Python version: ${GREEN}$(python3 --version)${NC}"
echo -e "Pip version: ${GREEN}$(python3 -m pip --version | cut -d' ' -f1,2)${NC}"
echo -e "\n${YELLOW}Installed packages:${NC}"
python3 -m pip list | grep -E "requests|beautifulsoup|paramiko|colorama|urllib3|lxml|cryptography"

echo -e "\n${BLUE}To test your Python script:${NC}"
echo -e "1. ${GREEN}python3 test_deps.py${NC} - test dependencies"
echo -e "2. ${GREEN}python3 your_script.py${NC} - run your actual script"

# Bersihkan file sementara
rm -f /tmp/python-deps.txt

echo -e "\n${YELLOW}Done!${NC}"
