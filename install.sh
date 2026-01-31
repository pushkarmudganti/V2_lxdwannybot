#!/bin/bash
# ======================================================
# PVM Node Manager v2.0 - Professional Installation Script
# Advanced OS Detection & System Installation
# Powered by WANNY DRAGON
# ======================================================

# Clear screen and show professional banner
clear
echo ""
echo -e "\e[1;35m"
echo "██████╗ ██╗   ██╗███╗   ███╗    ███╗   ██╗ ██████╗ ██████╗ ███████╗"
echo "██╔══██╗██║   ██║████╗ ████║    ████╗  ██║██╔═══██╗██╔══██╗██╔════╝"
echo "██████╔╝██║   ██║██╔████╔██║    ██╔██╗ ██║██║   ██║██║  ██║█████╗  "
echo "██╔═══╝ ██║   ██║██║╚██╔╝██║    ██║╚██╗██║██║   ██║██║  ██║██╔══╝  "
echo "██║     ╚██████╔╝██║ ╚═╝ ██║    ██║ ╚████║╚██████╔╝██████╔╝███████╗"
echo "╚═╝      ╚═════╝ ╚═╝     ╚═╝    ╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚══════╝"
echo ""
echo -e "\e[1;36m╔═══════════════════════════════════════════════════════════════════╗"
echo -e "║                         🆅ⒺⓇⓈⒾⓄⓃ 2.0                              ║"
echo -e "║                  🎯 ULTIMATE NODE MANAGEMENT                        ║"
echo -e "╚═══════════════════════════════════════════════════════════════════╝\e[0m"
echo ""

# Color Definitions (Professional)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Status Indicators
CHECK="${GREEN}[✓]${NC}"
CROSS="${RED}[✗]${NC}"
WARN="${YELLOW}[!]${NC}"
INFO="${BLUE}[i]${NC}"
GEAR="${CYAN}[⚙]${NC}"
ROCKET="${GREEN}[🚀]${NC}"
CLOUD="${BLUE}[☁]${NC}"
COMPUTER="${CYAN}[💻]${NC}"

# Print Functions
print_header() {
    echo ""
    echo -e "${PURPLE}======================================================${NC}"
    echo -e "  $1"
    echo -e "${PURPLE}======================================================${NC}"
    echo ""
}

print_step() {
    printf "${GEAR} ${BOLD}%-60s${NC}" "$1"
}

print_success() {
    echo -e "${CHECK} ${GREEN}$1${NC}"
}

print_error() {
    echo -e "${CROSS} ${RED}$1${NC}"
}

print_warning() {
    echo -e "${WARN} ${YELLOW}$1${NC}"
}

print_info() {
    echo -e "${INFO} ${BLUE}$1${NC}"
}

print_divider() {
    echo -e "${CYAN}------------------------------------------------------${NC}"
}

print_progress() {
    local current=$1
    local total=$2
    local text="$3"
    local width=50
    local percent=$((current * 100 / total))
    local completed=$((current * width / total))
    local remaining=$((width - completed))
    
    printf "\r${CYAN}["
    for ((i=0; i<completed; i++)); do printf "█"; done
    for ((i=0; i<remaining; i++)); do printf "░"; done
    printf "] %3d%% - %-30s${NC}" $percent "$text"
    
    if [ $current -eq $total ]; then
        echo ""
    fi
}

# ======================================================
# ADVANCED OS DETECTION MODULE
# ======================================================
detect_operating_system() {
    print_header "OPERATING SYSTEM DETECTION"
    
    # Initialize detection variables
    local os_name=""
    local os_id=""
    local os_version=""
    local os_version_id=""
    local os_codename=""
    local os_family=""
    local os_arch=""
    local os_kernel=""
    local package_manager=""
    
    print_step "Detecting system information..."
    echo ""
    
    # Get system architecture
    os_arch=$(uname -m)
    print_success "Architecture: $os_arch"
    
    # Get kernel version
    os_kernel=$(uname -r)
    print_success "Kernel: $os_kernel"
    
    # Method 1: /etc/os-release (Standard for modern Linux)
    if [ -f /etc/os-release ]; then
        print_info "Using /etc/os-release for detection"
        
        # Load the os-release file
        . /etc/os-release
        
        os_name="$NAME"
        os_id="$ID"
        os_version_id="$VERSION_ID"
        os_version="$PRETTY_NAME"
        
        # Get codename
        if [ -n "$VERSION_CODENAME" ]; then
            os_codename="$VERSION_CODENAME"
        elif [ -n "$UBUNTU_CODENAME" ]; then
            os_codename="$UBUNTU_CODENAME"
        fi
        
        print_success "OS: $os_name"
        print_success "ID: $os_id"
        print_success "Version: $os_version_id"
        [ -n "$os_codename" ] && print_success "Codename: $os_codename"
        
    # Method 2: /etc/lsb-release (Ubuntu/Debian)
    elif [ -f /etc/lsb-release ]; then
        print_info "Using /etc/lsb-release for detection"
        
        . /etc/lsb-release
        os_name="$DISTRIB_ID"
        os_id=$(echo "$DISTRIB_ID" | tr '[:upper:]' '[:lower:]')
        os_version_id="$DISTRIB_RELEASE"
        os_version="$DISTRIB_DESCRIPTION"
        os_codename="$DISTRIB_CODENAME"
        
        print_success "OS: $os_name"
        print_success "Version: $os_version_id"
        print_success "Codename: $os_codename"
        
    # Method 3: Distribution-specific files
    elif [ -f /etc/debian_version ]; then
        print_info "Detected via /etc/debian_version"
        
        os_name="Debian"
        os_id="debian"
        os_version_id=$(cat /etc/debian_version)
        os_version="Debian $os_version_id"
        
        # Determine Debian codename
        if echo "$os_version_id" | grep -q "^10"; then
            os_codename="buster"
        elif echo "$os_version_id" | grep -q "^11"; then
            os_codename="bullseye"
        elif echo "$os_version_id" | grep -q "^12"; then
            os_codename="bookworm"
        fi
        
        print_success "OS: Debian"
        print_success "Version: $os_version_id"
        print_success "Codename: $os_codename"
        
    elif [ -f /etc/redhat-release ]; then
        print_info "Detected via /etc/redhat-release"
        
        os_name=$(cat /etc/redhat-release | sed 's/ release.*//')
        os_id=$(echo "$os_name" | tr '[:upper:]' '[:lower:]')
        os_version=$(cat /etc/redhat-release)
        
        # Extract version number
        if [[ "$os_version" =~ release[[:space:]]*([0-9]+) ]]; then
            os_version_id="${BASH_REMATCH[1]}"
        fi
        
        print_success "OS: $os_name"
        print_success "Version: $os_version_id"
        
    elif [ -f /etc/arch-release ]; then
        print_info "Detected via /etc/arch-release"
        
        os_name="Arch Linux"
        os_id="arch"
        os_version="Rolling Release"
        
        print_success "OS: Arch Linux"
        print_success "Version: Rolling Release"
        
    else
        print_error "Could not detect operating system"
        print_info "Manual system configuration required"
        return 1
    fi
    
    # Determine OS family and package manager
    case "$os_id" in
        ubuntu|debian|linuxmint|pop|elementary|zorin|kali|parrot)
            os_family="debian"
            package_manager="apt"
            print_success "Package Manager: APT (Debian Family)"
            ;;
        centos|rhel|fedora|rocky|almalinux|amazon|oracle)
            os_family="rhel"
            if command -v dnf >/dev/null 2>&1; then
                package_manager="dnf"
            else
                package_manager="yum"
            fi
            print_success "Package Manager: $package_manager (RHEL Family)"
            ;;
        arch|manjaro|endeavouros)
            os_family="arch"
            package_manager="pacman"
            print_success "Package Manager: Pacman (Arch Family)"
            ;;
        opensuse*|sles)
            os_family="suse"
            package_manager="zypper"
            print_success "Package Manager: Zypper (SUSE Family)"
            ;;
        alpine)
            os_family="alpine"
            package_manager="apk"
            print_success "Package Manager: APK (Alpine)"
            ;;
        *)
            os_family="unknown"
            package_manager="unknown"
            print_warning "Unknown OS family, manual package manager setup required"
            ;;
    esac
    
    # Export variables for use in other functions
    export OS_NAME="$os_name"
    export OS_ID="$os_id"
    export OS_VERSION="$os_version"
    export OS_VERSION_ID="$os_version_id"
    export OS_CODENAME="$os_codename"
    export OS_FAMILY="$os_family"
    export OS_ARCH="$os_arch"
    export OS_KERNEL="$os_kernel"
    export PACKAGE_MANAGER="$package_manager"
    
    print_divider
    return 0
}

# ======================================================
# SYSTEM REQUIREMENTS CHECK
# ======================================================
check_system_requirements() {
    print_header "SYSTEM REQUIREMENTS CHECK"
    
    local requirements_met=true
    
    # Check RAM
    print_step "Checking RAM requirements..."
    local ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local ram_gb=$((ram_kb / 1024 / 1024))
    
    if [ $ram_gb -ge 2 ]; then
        print_success "RAM: ${ram_gb}GB (Minimum: 2GB)"
    else
        print_error "Insufficient RAM: ${ram_gb}GB (Minimum: 2GB)"
        requirements_met=false
    fi
    
    # Check disk space
    print_step "Checking disk space..."
    local disk_space_kb=$(df / | tail -1 | awk '{print $4}')
    local disk_space_gb=$((disk_space_kb / 1024 / 1024))
    
    if [ $disk_space_gb -ge 20 ]; then
        print_success "Disk Space: ${disk_space_gb}GB (Minimum: 20GB)"
    else
        print_error "Insufficient disk space: ${disk_space_gb}GB (Minimum: 20GB)"
        requirements_met=false
    fi
    
    # Check CPU cores
    print_step "Checking CPU cores..."
    local cpu_cores=$(nproc)
    
    if [ $cpu_cores -ge 2 ]; then
        print_success "CPU Cores: ${cpu_cores} (Minimum: 2)"
    else
        print_warning "Low CPU cores: ${cpu_cores} (Recommended: 2+)"
    fi
    
    # Check internet connection
    print_step "Checking internet connection..."
    if ping -c 1 8.8.8.8 &> /dev/null; then
        print_success "Internet connection: OK"
    else
        print_warning "No internet connection detected"
    fi
    
    print_divider
    
    if [ "$requirements_met" = false ]; then
        print_error "System requirements not met. Installation cannot continue."
        return 1
    fi
    
    print_success "All system requirements satisfied"
    return 0
}

# ======================================================
# OS-SPECIFIC INSTALLATION FUNCTIONS
# ======================================================
install_for_ubuntu() {
    local version="$1"
    print_header "UBUNTU $version INSTALLATION"
    
    case "$version" in
        22.04|"22.04 LTS"|jammy)
            install_ubuntu_2204
            ;;
        20.04|"20.04 LTS"|focal)
            install_ubuntu_2004
            ;;
        18.04|"18.04 LTS"|bionic)
            install_ubuntu_1804
            ;;
        *)
            print_error "Unsupported Ubuntu version: $version"
            return 1
            ;;
    esac
}

install_ubuntu_2204() {
    print_step "Installing for Ubuntu 22.04 LTS (Jammy Jellyfish)..."
    echo ""
    
    # Update system
    print_step "Updating package lists..."
    apt update -y
    print_success "Package lists updated"
    
    # Install system dependencies
    print_step "Installing system dependencies..."
    apt install -y \
        curl \
        wget \
        git \
        nano \
        htop \
        screen \
        tmux \
        ufw \
        net-tools \
        dnsutils \
        gnupg \
        software-properties-common \
        apt-transport-https \
        ca-certificates \
        lsb-release
    print_success "System dependencies installed"
    
    # Install Python
    print_step "Installing Python..."
    apt install -y \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        python3-wheel \
        python3-setuptools
    print_success "Python installed"
    
    # Install LXD dependencies
    print_step "Installing LXD dependencies..."
    apt install -y \
        bridge-utils \
        uidmap \
        dnsmasq-base \
        squashfs-tools \
        lvm2 \
        thin-provisioning-tools
    print_success "LXD dependencies installed"
    
    # Install snapd if not present
    if ! command -v snap &> /dev/null; then
        print_step "Installing snapd..."
        apt install -y snapd
        systemctl enable --now snapd.socket
        print_success "snapd installed"
    fi
    
    print_success "Ubuntu 22.04 setup complete"
    return 0
}

install_ubuntu_2004() {
    print_step "Installing for Ubuntu 20.04 LTS (Focal Fossa)..."
    echo ""
    
    # Similar to 22.04 but with potential version-specific adjustments
    apt update -y
    apt install -y \
        curl wget git nano htop screen tmux ufw net-tools \
        python3 python3-pip python3-venv python3-dev \
        bridge-utils uidmap dnsmasq-base squashfs-tools \
        snapd
    
    systemctl enable --now snapd.socket
    
    print_success "Ubuntu 20.04 setup complete"
    return 0
}

install_for_debian() {
    local version="$1"
    print_header "DEBIAN $version INSTALLATION"
    
    apt update -y
    apt install -y \
        curl wget git nano htop screen tmux \
        python3 python3-pip python3-venv \
        bridge-utils uidmap dnsmasq \
        snapd
    
    systemctl enable --now snapd.socket
    
    print_success "Debian $version setup complete"
    return 0
}

install_for_centos() {
    local version="$1"
    print_header "CENTOS $version INSTALLATION"
    
    if command -v dnf &> /dev/null; then
        dnf update -y
        dnf install -y \
            curl wget git nano htop tmux \
            python3 python3-pip python3-virtualenv \
            bridge-utils uidmap dnsmasq \
            epel-release
    else
        yum update -y
        yum install -y \
            curl wget git nano htop tmux \
            python3 python3-pip python3-virtualenv \
            bridge-utils uidmap dnsmasq \
            epel-release
    fi
    
    # Install snapd from EPEL
    yum install -y snapd
    systemctl enable --now snapd.socket
    ln -s /var/lib/snapd/snap /snap
    
    print_success "CentOS $version setup complete"
    return 0
}

# ======================================================
# MAIN INSTALLATION FUNCTION
# ======================================================
main_installation() {
    print_header "STARTING INSTALLATION PROCESS"
    
    # Step 1: Detect OS
    if ! detect_operating_system; then
        print_error "Failed to detect operating system"
        exit 1
    fi
    
    # Step 2: Check requirements
    if ! check_system_requirements; then
        print_error "System requirements check failed"
        exit 1
    fi
    
    # Step 3: OS-specific installation
    print_header "INITIATING OS-SPECIFIC INSTALLATION"
    
    case "$OS_ID" in
        ubuntu)
            install_for_ubuntu "$OS_VERSION_ID"
            ;;
        debian)
            install_for_debian "$OS_VERSION_ID"
            ;;
        centos|rhel)
            install_for_centos "$OS_VERSION_ID"
            ;;
        fedora)
            print_step "Installing for Fedora..."
            dnf install -y curl wget git python3 python3-pip snapd
            print_success "Fedora setup complete"
            ;;
        arch)
            print_step "Installing for Arch Linux..."
            pacman -Syu --noconfirm
            pacman -S --noconfirm curl wget git python python-pip snapd
            print_success "Arch Linux setup complete"
            ;;
        *)
            print_error "Unsupported operating system: $OS_NAME"
            print_info "Manual installation required for $OS_NAME"
            exit 1
            ;;
    esac
    
    # Step 4: Install LXD
    print_header "INSTALLING LXD CONTAINER PLATFORM"
    
    print_step "Installing LXD via snap..."
    snap install lxd --channel=latest/stable
    
    if [ $? -eq 0 ]; then
        print_success "LXD installed successfully"
    else
        print_error "Failed to install LXD"
        exit 1
    fi
    
    # Step 5: Initialize LXD
    print_step "Initializing LXD..."
    lxd init --auto
    
    if [ $? -eq 0 ]; then
        print_success "LXD initialized successfully"
    else
        print_warning "LXD initialization returned non-zero, but continuing..."
    fi
    
    # Step 6: Setup Python virtual environment
    print_header "SETTING UP PYTHON ENVIRONMENT"
    
    print_step "Creating virtual environment..."
    python3 -m venv venv
    
    if [ $? -eq 0 ]; then
        print_success "Virtual environment created"
    else
        print_error "Failed to create virtual environment"
        exit 1
    fi
    
    print_step "Activating virtual environment..."
    source venv/bin/activate
    
    print_step "Installing Python packages..."
    pip install --upgrade pip
    pip install discord.py PyNaCl psutil requests
    
    if [ $? -eq 0 ]; then
        print_success "Python packages installed"
    else
        print_error "Failed to install Python packages"
        exit 1
    fi
    
    # Step 7: Create directory structure
    print_header "CREATING DIRECTORY STRUCTURE"
    
    local dirs=("data" "logs" "backups" "configs" "scripts")
    
    for dir in "${dirs[@]}"; do
        print_step "Creating $dir directory..."
        mkdir -p "$dir"
        print_success "$dir directory created"
    done
    
    # Step 8: Create configuration files
    print_header "CREATING CONFIGURATION FILES"
    
    # Create sample config if it doesn't exist
    if [ ! -f "config.py" ]; then
        print_step "Creating sample configuration..."
        cat > config.example.py << 'EOF'
# PVM Node Manager Configuration
# ================================

# Discord Bot Settings
DISCORD_TOKEN = "YOUR_BOT_TOKEN_HERE"
BOT_NAME = "PVM Node Manager"
PREFIX = "!"
MAIN_ADMIN_ID = "YOUR_DISCORD_ID_HERE"

# System Settings
DEFAULT_STORAGE_POOL = "default"
MAX_NODES_PER_USER = 5

# Server Information
YOUR_SERVER_IP = "YOUR_SERVER_IP_HERE"

# Purge System Settings
PURGE_ENABLED = True
PURGE_MIN_AGE_DAYS = 30
PURGE_MAX_INACTIVE_DAYS = 14
PURGE_DRY_RUN = True

# Node Defaults
DEFAULT_RAM = "2GB"
DEFAULT_CPU = "2"
DEFAULT_STORAGE = "20GB"
DEFAULT_OS = "ubuntu:22.04"
EOF
        print_success "Sample configuration created (config.example.py)"
        print_info "Please copy to config.py and edit with your settings"
    fi
    
    # Create requirements file
    print_step "Creating requirements.txt..."
    cat > requirements.txt << 'EOF'
discord.py>=2.3.0
PyNaCl>=1.5.0
psutil>=5.9.0
requests>=2.28.0
EOF
    print_success "requirements.txt created"
    
    # Step 9: Create startup script
    print_header "CREATING STARTUP SCRIPTS"
    
    cat > start.sh << 'EOF'
#!/bin/bash
# PVM Node Manager Startup Script

# Check if running in correct directory
if [ ! -f "bot.py" ]; then
    echo "Error: bot.py not found. Run this script from the bot directory."
    exit 1
fi

# Check virtual environment
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install requirements if needed
if ! pip list | grep -q discord.py; then
    echo "Installing requirements..."
    pip install -r requirements.txt
fi

# Check configuration
if [ ! -f "config.py" ]; then
    if [ -f "config.example.py" ]; then
        echo "Copying example configuration..."
        cp config.example.py config.py
        echo ""
        echo "IMPORTANT: Please edit config.py and add your Discord token!"
        echo "Run: nano config.py"
        exit 1
    else
        echo "Error: No configuration file found."
        exit 1
    fi
fi

# Run the bot
echo "Starting PVM Node Manager..."
python3 bot.py
EOF
    
    chmod +x start.sh
    print_success "Startup script created (start.sh)"
    
    # Create systemd service file
    cat > pvm-node-manager.service << EOF
[Unit]
Description=PVM Node Manager Discord Bot
After=network.target lxd.service
Requires=lxd.service

[Service]
Type=simple
User=$SUDO_USER
WorkingDirectory=$(pwd)
ExecStart=$(pwd)/venv/bin/python3 bot.py
Restart=always
RestartSec=10
StandardOutput=append:$(pwd)/logs/bot.log
StandardError=append:$(pwd)/logs/error.log
Environment="PYTHONUNBUFFERED=1"

[Install]
WantedBy=multi-user.target
EOF
    
    print_success "Systemd service file created"
    
    # Final steps
    print_header "INSTALLATION COMPLETE"
    
    echo -e "${GREEN}${BOLD}Installation completed successfully!${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Edit the configuration file:"
    echo "   cp config.example.py config.py"
    echo "   nano config.py"
    echo ""
    echo "2. Add your Discord bot token and admin ID to config.py"
    echo ""
    echo "3. Start the bot:"
    echo "   ./start.sh"
    echo ""
    echo "4. Or install as a system service:"
    echo "   sudo cp pvm-node-manager.service /etc/systemd/system/"
    echo "   sudo systemctl daemon-reload"
    echo "   sudo systemctl enable pvm-node-manager"
    echo "   sudo systemctl start pvm-node-manager"
    echo ""
    echo "5. Check logs:"
    echo "   tail -f logs/bot.log"
    echo ""
    echo "For support, check the documentation or create an issue."
    echo ""
    echo -e "${CYAN}Thank you for choosing PVM Node Manager!${NC}"
}

# ======================================================
# SCRIPT ENTRY POINT
# ======================================================
main() {
    # Show banner
    clear
    echo ""
    echo -e "\e[1;35m"
    echo "██████╗ ██╗   ██╗███╗   ███╗    ███╗   ██╗ ██████╗ ██████╗ ███████╗"
    echo "██╔══██╗██║   ██║████╗ ████║    ████╗  ██║██╔═══██╗██╔══██╗██╔════╝"
    echo "██████╔╝██║   ██║██╔████╔██║    ██╔██╗ ██║██║   ██║██║  ██║█████╗  "
    echo "██╔═══╝ ██║   ██║██║╚██╔╝██║    ██║╚██╗██║██║   ██║██║  ██║██╔══╝  "
    echo "██║     ╚██████╔╝██║ ╚═╝ ██║    ██║ ╚████║╚██████╔╝██████╔╝███████╗"
    echo "╚═╝      ╚═════╝ ╚═╝     ╚═╝    ╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚══════╝"
    echo ""
    echo -e "\e[1;36m╔═══════════════════════════════════════════════════════════════════╗"
    echo -e "║                         🆅ⒺⓇⓈⒾⓄⓃ 2.0                              ║"
    echo -e "║                  🎯 ULTIMATE NODE MANAGEMENT                        ║"
    echo -e "╚═══════════════════════════════════════════════════════════════════╝\e[0m"
    echo ""
    
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then 
        echo -e "${RED}${BOLD}This script must be run as root!${NC}"
        echo "Usage: sudo bash install.sh"
        exit 1
    fi
    
    # Start installation
    main_installation
}

# Run the main function
main
