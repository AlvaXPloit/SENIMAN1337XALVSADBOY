#!/bin/bash
# Auto Install Python Dependencies - FINAL FIX
# Cara pakai: bash -c "$(curl -fsSL https://raw.githubusercontent.com/USERNAME/REPO/main/install-python-deps-final.sh)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}  Auto Install Python Dependencies (FINAL)${NC}"
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

# Update package list
echo -e "\n${YELLOW}[1] Updating package list...${NC}"
apt-get update -y

# Install system packages
echo -e "\n${YELLOW}[2] Installing system packages...${NC}"
apt-get install -y python3 python3-pip python3-venv python3-dev build-essential \
    libssl-dev libffi-dev wget curl git netcat-openbsd nmap sshpass openssh-client \
    net-tools dnsutils

# Upgrade pip
echo -e "\n${YELLOW}[3] Upgrading pip...${NC}"
python3 -m pip install --upgrade pip setuptools wheel

# Install Python dependencies - CLEAN VERSION
echo -e "\n${YELLOW}[4] Installing Python dependencies...${NC}"

# Buat requirements.txt yang bersih (tanpa komentar)
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

# Tampilkan isi requirements
echo -e "${BLUE}Requirements:${NC}"
cat requirements.txt

# Install dengan berbagai metode
echo -e "\n${YELLOW}[5] Installing with pip...${NC}"

# Metode 1: Install dengan --break-system-packages (untuk Ubuntu 24.04+)
python3 -m pip install --upgrade --break-system-packages -r requirements.txt 2>/dev/null

if [ $? -ne 0 ]; then
    # Metode 2: Install normal
    python3 -m pip install --upgrade -r requirements.txt 2>/dev/null
fi

if [ $? -ne 0 ]; then
    # Metode 3: Install satu per satu
    echo -e "${YELLOW}Installing one by one...${NC}"
    python3 -m pip install --upgrade requests
    python3 -m pip install --upgrade beautifulsoup4
    python3 -m pip install --upgrade paramiko
    python3 -m pip install --upgrade colorama
    python3 -m pip install --upgrade urllib3
    python3 -m pip install --upgrade lxml
    python3 -m pip install --upgrade cryptography
    python3 -m pip install --upgrade pyOpenSSL
fi

# Verifikasi instalasi
echo -e "\n${YELLOW}[6] Verifying installation...${NC}"

# Buat script verifikasi Python
python3 << 'EOF'
import sys
import importlib.util
import subprocess

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
    try:
        if module_name == 'bs4':
            import bs4
            version = getattr(bs4, '__version__', 'unknown')
        elif module_name == 'OpenSSL':
            import OpenSSL
            version = OpenSSL.__version__
        else:
            module = __import__(module_name)
            version = getattr(module, '__version__', 'unknown')
        print(f'\033[0;32m✓ {package_name} {version}\033[0m')
    except ImportError as e:
        print(f'\033[0;31m✗ {package_name} NOT FOUND: {e}\033[0m')
        all_good = False

# Cek built-in modules
builtins = ['re', 'sys', 'os', 'socket', 'datetime', 'threading', 'concurrent.futures', 'urllib.parse']
for module in builtins:
    try:
        __import__(module)
        print(f'\033[0;32m✓ {module} (built-in)\033[0m')
    except ImportError:
        print(f'\033[0;31m✗ {module} (built-in) not available\033[0m')
        all_good = False

if all_good:
    print(f'\n\033[0;32m✓ All dependencies verified!\033[0m')
    sys.exit(0)
else:
    print(f'\n\033[0;31m✗ Some dependencies are missing\033[0m')
    
    # Tampilkan pip list untuk debugging
    print(f'\n\033[1;33mInstalled packages via pip:\033[0m')
    result = subprocess.run([sys.executable, '-m', 'pip', 'list'], capture_output=True, text=True)
    for line in result.stdout.split('\n'):
        if any(pkg in line.lower() for pkg in ['requests', 'beautifulsoup', 'paramiko', 'colorama', 'urllib3', 'lxml', 'cryptography', 'openssl']):
            print(f'  {line}')
    
    sys.exit(1)
EOF

# Jika masih gagal, coba install dengan apt
if [ $? -ne 0 ]; then
    echo -e "\n${YELLOW}[7] Trying system packages as fallback...${NC}"
    apt-get install -y python3-requests python3-bs4 python3-paramiko python3-colorama \
        python3-urllib3 python3-lxml python3-cryptography python3-openssl
fi

# Buat script test sederhana
echo -e "\n${YELLOW}[8] Creating test script...${NC}"
cat > test_deps.py << 'EOF'
#!/usr/bin/env python3
"""
Test script untuk memverifikasi semua dependencies
"""
import sys
import importlib.metadata

def print_version(package_name, import_name=None):
    if import_name is None:
        import_name = package_name
    
    try:
        if import_name == 'bs4':
            from bs4 import BeautifulSoup
            version = importlib.metadata.version('beautifulsoup4')
        elif import_name == 'OpenSSL':
            import OpenSSL
            version = OpenSSL.__version__
        else:
            module = __import__(import_name)
            version = getattr(module, '__version__', importlib.metadata.version(package_name))
        print(f"✓ {package_name}: {version}")
        return True
    except (ImportError, importlib.metadata.PackageNotFoundError) as e:
        print(f"✗ {package_name}: {e}")
        return False

print("Testing Python dependencies:")
print("-" * 50)

# Test imports
tests = [
    ('requests', 'requests'),
    ('beautifulsoup4', 'bs4'),
    ('paramiko', 'paramiko'),
    ('colorama', 'colorama'),
    ('urllib3', 'urllib3'),
    ('lxml', 'lxml'),
    ('cryptography', 'cryptography'),
    ('pyOpenSSL', 'OpenSSL')
]

success = True
for package, import_name in tests:
    if not print_version(package, import_name):
        success = False

print("-" * 50)
if success:
    print("✅ All dependencies installed successfully!")
    print("\nYou can now run your Python script:")
    print("  python3 your_script.py")
    sys.exit(0)
else:
    print("❌ Some dependencies are missing. Try installing manually:")
    print("  python3 -m pip install --user requests beautifulsoup4 paramiko colorama urllib3 lxml cryptography pyOpenSSL")
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
echo -e "Pip: ${GREEN}$(python3 -m pip --version | cut -d' ' -f1,2)${NC}"
echo -e "\n${YELLOW}Pip list:${NC}"
python3 -m pip list | grep -E "requests|beautifulsoup|paramiko|colorama|urllib3|lxml|cryptography|OpenSSL" || echo "No packages found"

echo -e "\n${BLUE}To use your Python script:${NC}"
echo -e "1. ${GREEN}python3 test_deps.py${NC} - test dependencies"
echo -e "2. ${GREEN}python3 your_script.py${NC} - run your actual script"

echo -e "\n${YELLOW}If you still have issues, try:${NC}"
echo -e "  ${GREEN}python3 -m pip install --user -r requirements.txt${NC}"
