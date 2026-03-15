#!/bin/bash
# Auto Install Python Dependencies - FIXED VERSION
# Cara pakai: bash -c "$(curl -fsSL https://raw.githubusercontent.com/USERNAME/REPO/main/install-python-deps-fixed.sh)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}  Auto Install Python Dependencies (FIXED)${NC}"
echo -e "${BLUE}========================================${NC}"

# Deteksi OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    else
        OS=$(uname -s)
    fi
    echo "$OS"
}

OS_TYPE=$(detect_os)
echo -e "${YELLOW}Detected OS: $OS_TYPE${NC}"

# Install system packages dengan force
echo -e "\n${YELLOW}[1] Installing system packages...${NC}"
case $OS_TYPE in
    ubuntu|debian)
        apt-get update -y
        apt-get install -y python3 python3-pip python3-venv python3-dev build-essential libssl-dev libffi-dev wget curl git
        ;;
    centos|rhel|fedora|almalinux)
        yum install -y epel-release
        yum install -y python3 python3-pip python3-devel gcc openssl-devel libffi-devel wget curl git
        ;;
    *)
        apt-get update -y 2>/dev/null || yum update -y 2>/dev/null
        apt-get install -y python3 python3-pip 2>/dev/null || yum install -y python3 python3-pip 2>/dev/null
        ;;
esac

# Upgrade pip dengan force
echo -e "\n${YELLOW}[2] Upgrading pip...${NC}"
python3 -m pip install --upgrade pip --break-system-packages 2>/dev/null || python3 -m pip install --upgrade pip

# Install dependencies SATU PER SATU dengan verbose
echo -e "\n${YELLOW}[3] Installing Python dependencies one by one...${NC}"

# Array of packages to install
PACKAGES=(
    "requests"
    "beautifulsoup4"
    "paramiko"
    "colorama"
    "urllib3"
    "lxml"
    "cryptography"
    "pyOpenSSL"
)

# Install each package individually
for package in "${PACKAGES[@]}"; do
    echo -e "${BLUE}Installing $package...${NC}"
    
    # Coba berbagai metode instalasi
    python3 -m pip install --upgrade "$package" --break-system-packages 2>/dev/null || \
    python3 -m pip install --upgrade "$package" --ignore-installed 2>/dev/null || \
    python3 -m pip install "$package" 2>/dev/null || \
    pip3 install "$package" 2>/dev/null || \
    echo -e "${RED}Failed to install $package${NC}"
    
    # Verifikasi instalasi
    python3 -c "import $package" 2>/dev/null && echo -e "${GREEN}✓ $package installed${NC}" || echo -e "${RED}✗ $package failed${NC}"
done

# Install via requirements file sebagai backup
echo -e "\n${YELLOW}[4] Installing via requirements file...${NC}"
cat > requirements.txt << 'EOF'
requests>=2.31.0
beautifulsoup4>=4.12.0
paramiko>=3.4.0
colorama>=0.4.6
urllib3>=2.2.0
lxml>=5.1.0
cryptography>=42.0.0
pyOpenSSL>=24.0.0
EOF

python3 -m pip install --upgrade -r requirements.txt --break-system-packages 2>/dev/null || \
python3 -m pip install -r requirements.txt

# Install dengan force menggunakan --no-cache-dir
echo -e "\n${YELLOW}[5] Force installing with --no-cache-dir...${NC}"
python3 -m pip install --no-cache-dir --upgrade -r requirements.txt --break-system-packages 2>/dev/null || \
python3 -m pip install --no-cache-dir -r requirements.txt

# Verifikasi final dengan script Python
echo -e "\n${YELLOW}[6] Final verification...${NC}"
python3 << 'EOF'
import sys
import importlib.util

packages = [
    ('requests', 'requests'),
    ('bs4', 'beautifulsoup4'),
    ('paramiko', 'paramiko'),
    ('colorama', 'colorama'),
    ('urllib3', 'urllib3'),
    ('lxml', 'lxml'),
    ('cryptography', 'cryptography'),
    ('OpenSSL', 'pyOpenSSL')
]

print('\033[1;33mTesting imports:\033[0m')
all_good = True

for module_name, package_name in packages:
    spec = importlib.util.find_spec(module_name)
    if spec is not None:
        print(f'\033[0;32m✓ {package_name} found at {spec.origin}\033[0m')
    else:
        print(f'\033[0;31m✗ {package_name} NOT FOUND\033[0m')
        all_good = False

# Cek lokasi instalasi pip
import subprocess
result = subprocess.run([sys.executable, '-m', 'pip', 'list'], capture_output=True, text=True)
print(f'\n\033[1;33mPip installed packages:\033[0m')
for line in result.stdout.split('\n'):
    if any(pkg in line.lower() for pkg in ['requests', 'beautifulsoup', 'paramiko', 'colorama', 'urllib3', 'lxml', 'cryptography', 'openssl']):
        print(f'  {line}')

if all_good:
    print(f'\n\033[0;32m✓ All dependencies verified!\033[0m')
    sys.exit(0)
else:
    print(f'\n\033[0;31m✗ Some dependencies are missing\033[0m')
    sys.exit(1)
EOF

# Jika masih gagal, coba install dengan apt (untuk Ubuntu/Debian)
if [ $? -ne 0 ]; then
    echo -e "\n${YELLOW}[7] Trying system packages as fallback...${NC}"
    case $OS_TYPE in
        ubuntu|debian)
            apt-get install -y python3-requests python3-bs4 python3-paramiko python3-colorama python3-urllib3 python3-lxml python3-cryptography python3-openssl
            ;;
    esac
fi

# Buat script test sederhana
echo -e "\n${YELLOW}[8] Creating test script...${NC}"
cat > test_deps.py << 'EOF'
#!/usr/bin/env python3
"""
Test script untuk memverifikasi semua dependencies
"""
import sys
import os

def test_import(module_name, package_name):
    try:
        if module_name == 'bs4':
            from bs4 import BeautifulSoup
            print(f"✓ {package_name}: {BeautifulSoup.__version__ if hasattr(BeautifulSoup, '__version__') else 'OK'}")
        elif module_name == 'OpenSSL':
            import OpenSSL
            print(f"✓ {package_name}: {OpenSSL.__version__}")
        else:
            module = __import__(module_name)
            version = getattr(module, '__version__', 'unknown')
            print(f"✓ {package_name}: {version}")
        return True
    except ImportError as e:
        print(f"✗ {package_name}: {e}")
        return False

print("Testing Python dependencies:")
print("-" * 40)

# Test imports
tests = [
    ('requests', 'requests'),
    ('bs4', 'beautifulsoup4'),
    ('paramiko', 'paramiko'),
    ('colorama', 'colorama'),
    ('urllib3', 'urllib3'),
    ('lxml', 'lxml'),
    ('cryptography', 'cryptography'),
    ('OpenSSL', 'pyOpenSSL')
]

success = True
for module, package in tests:
    if not test_import(module, package):
        success = False

print("-" * 40)
if success:
    print("✅ All dependencies installed successfully!")
    sys.exit(0)
else:
    print("❌ Some dependencies are missing. Check the errors above.")
    sys.exit(1)
EOF

chmod +x test_deps.py
echo -e "${GREEN}✓ Test script created: ./test_deps.py${NC}"

# Jalankan test script
echo -e "\n${YELLOW}[9] Running test script...${NC}"
python3 test_deps.py

# Tampilkan hasil akhir
echo -e "\n${BLUE}========================================${NC}"
echo -e "${GREEN}Installation Complete!${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "Python: ${GREEN}$(python3 --version)${NC}"
echo -e "Pip: ${GREEN}$(python3 -m pip --version)${NC}"
echo -e "\n${YELLOW}Installed packages:${NC}"
python3 -m pip list | grep -E "requests|beautifulsoup|paramiko|colorama|urllib3|lxml|cryptography|OpenSSL" || echo "No packages found via pip"

echo -e "\n${BLUE}To use your Python script:${NC}"
echo -e "1. ${GREEN}python3 test_deps.py${NC} - test dependencies"
echo -e "2. ${GREEN}python3 your_script.py${NC} - run your actual script"

echo -e "\n${YELLOW}If dependencies still missing, try:${NC}"
echo -e "  ${GREEN}python3 -m pip install --user requests beautifulsoup4 paramiko colorama urllib3 lxml cryptography pyOpenSSL${NC}"
