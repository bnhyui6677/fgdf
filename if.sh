#!/bin/bash
#############################################################################
#                          MEHRAZ VM Manager                                #
#           Cloud VM Creation and Management Script for Linux               #
#                                                                           #
#  This script creates and manages QEMU/KVM virtual machines using         #
#  cloud images. It supports creating up to 30 VMs with custom             #
#  configurations including hostname, SSH port, and user accounts.         #
#                                                                           #
#  Author: mehraz                                                           #
#  License: MIT                                                             #
#############################################################################

set -euo pipefail

# ========================== CONFIGURATION ==========================

# Base directory for VM storage
VM_BASE_DIR="${HOME}/mehraz-vms"
IMAGES_DIR="${VM_BASE_DIR}/images"
VMS_DIR="${VM_BASE_DIR}/vms"
CONFIG_DIR="${VM_BASE_DIR}/configs"

# Supported cloud images with download URLs
declare -A CLOUD_IMAGES=(
    ["ubuntu2404"]="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
    ["ubuntu2204"]="https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
    ["ubuntu2004"]="https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img"
    ["debian12"]="https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2"
    ["debian11"]="https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-generic-amd64.qcow2"
    ["centos9"]="https://cloud.centos.org/centos/9-stream/x86_64/images/CentOS-Stream-GenericCloud-9-latest.x86_64.qcow2"
    ["rocky9"]="https://download.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2"
    ["almalinux9"]="https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-latest.x86_64.qcow2"
    ["fedora40"]="https://download.fedoraproject.org/pub/fedora/linux/releases/40/Cloud/x86_64/images/Fedora-Cloud-Base-Generic.x86_64-40-1.14.qcow2"
)

# Maximum number of VMs that can be created in one session
MAX_VMS=30

# Default resource values
DEFAULT_RAM="256G"
DEFAULT_VCPUS="24"
DEFAULT_DISK="200G"

# Color codes for terminal output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly NC='\033[0m' # No Color
readonly BOLD='\033[1m'

# Array to store created VM information for final summary
declare -a CREATED_VMS=()

# Track used SSH ports in this session to prevent duplicates
declare -a USED_PORTS=()

# ========================== UTILITY FUNCTIONS ==========================

# Print a styled header banner
print_header() {
    local text="$1"
    local width=70
    local padding=$(( (width - ${#text} - 2) / 2 ))
    echo ""
    echo -e "${CYAN}$(printf '=%.0s' $(seq 1 $width))${NC}"
    echo -e "${CYAN}$(printf ' %.0s' $(seq 1 $padding)) ${BOLD}${text}${NC}${CYAN} $(printf ' %.0s' $(seq 1 $padding))${NC}"
    echo -e "${CYAN}$(printf '=%.0s' $(seq 1 $width))${NC}"
    echo ""
}

# Print informational message
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Print success message
print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Print warning message
print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Print error message
print_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Print a debug message (can be enabled for troubleshooting)
print_debug() {
    if [[ "${DEBUG:-0}" == "1" ]]; then
        echo -e "${MAGENTA}[DEBUG]${NC} $1"
    fi
}

# Cleanup function for graceful exit
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        print_error "Script exited with error code: ${exit_code}"
    fi
    exit $exit_code
}

trap cleanup EXIT

# ========================== SYSTEM CHECKS ==========================

# Check if the host CPU supports hardware virtualization (VT-x/AMD-V)
check_virtualization_support() {
    print_info "Checking CPU virtualization support..."
    
    # Check for Intel VT-x (vmx) or AMD-V (svm) CPU flags
    if ! grep -Eq '(vmx|svm)' /proc/cpuinfo 2>/dev/null; then
        print_error "CPU does not support hardware virtualization (VT-x/AMD-V)."
        print_error "Please enable virtualization in your BIOS/UEFI settings."
        print_error "Look for options like 'Intel VT-x', 'AMD-V', 'SVM', or 'Virtualization Technology'."
        exit 1
    fi
    
    # Determine CPU vendor for appropriate KVM module
    local cpu_vendor=""
    if grep -q 'vmx' /proc/cpuinfo; then
        cpu_vendor="intel"
    elif grep -q 'svm' /proc/cpuinfo; then
        cpu_vendor="amd"
    fi
    
    print_info "Detected ${cpu_vendor^^} CPU with virtualization support"
    
    # Check if KVM modules are loaded
    if ! lsmod | grep -q '^kvm'; then
        print_warning "KVM kernel module not loaded. Attempting to load..."
        
        if [[ "${cpu_vendor}" == "intel" ]]; then
            sudo modprobe kvm_intel 2>/dev/null || true
        elif [[ "${cpu_vendor}" == "amd" ]]; then
            sudo modprobe kvm_amd 2>/dev/null || true
        fi
        sudo modprobe kvm 2>/dev/null || true
        
        # Verify modules loaded
        if ! lsmod | grep -q '^kvm'; then
            print_error "Failed to load KVM modules."
            print_error "Please ensure your kernel supports KVM and modules are available."
            exit 1
        fi
    fi
    
    # Check for /dev/kvm device
    if [[ ! -e /dev/kvm ]]; then
        print_error "/dev/kvm device not found."
        print_error "KVM is not properly configured on this system."
        print_error "Please install KVM and ensure the kernel modules are loaded."
        exit 1
    fi
    
    # Check user permissions on /dev/kvm
    if [[ ! -r /dev/kvm ]] || [[ ! -w /dev/kvm ]]; then
        print_warning "Current user may not have full access to /dev/kvm"
        print_info "To fix, add your user to the 'kvm' group:"
        print_info "  sudo usermod -aG kvm \$USER"
        print_info "Then log out and log back in."
        print_info ""
        print_info "Attempting to continue anyway (may require sudo for VM operations)..."
    fi
    
    print_success "Virtualization support verified (KVM is available)"
}

# Check that all required dependencies are installed
check_dependencies() {
    print_info "Checking required dependencies..."
    
    local missing_deps=()
    local pkg_manager=""
    local install_instructions=""
    
    # Detect package manager
    if command -v apt-get &>/dev/null; then
        pkg_manager="apt"
        install_instructions="sudo apt-get update && sudo apt-get install -y qemu-system-x86 qemu-utils cloud-image-utils wget genisoimage openssl"
    elif command -v dnf &>/dev/null; then
        pkg_manager="dnf"
        install_instructions="sudo dnf install -y qemu-kvm qemu-img cloud-utils wget genisoimage openssl"
    elif command -v yum &>/dev/null; then
        pkg_manager="yum"
        install_instructions="sudo yum install -y qemu-kvm qemu-img cloud-utils wget genisoimage openssl"
    elif command -v pacman &>/dev/null; then
        pkg_manager="pacman"
        install_instructions="sudo pacman -S --noconfirm qemu-full cloud-image-utils wget cdrtools openssl"
    elif command -v zypper &>/dev/null; then
        pkg_manager="zypper"
        install_instructions="sudo zypper install -y qemu-kvm qemu-tools cloud-image-utils wget genisoimage openssl"
    else
        print_error "No supported package manager found (apt, dnf, yum, pacman, zypper)"
        exit 1
    fi
    
    print_debug "Detected package manager: ${pkg_manager}"
    
    # Check for qemu-system-x86_64
    if ! command -v qemu-system-x86_64 &>/dev/null; then
        missing_deps+=("qemu-system-x86_64")
        print_debug "Missing: qemu-system-x86_64"
    fi
    
    # Check for qemu-img
    if ! command -v qemu-img &>/dev/null; then
        missing_deps+=("qemu-img")
        print_debug "Missing: qemu-img"
    fi
    
    # Check for cloud-localds (part of cloud-image-utils)
    if ! command -v cloud-localds &>/dev/null; then
        missing_deps+=("cloud-localds (cloud-image-utils)")
        print_debug "Missing: cloud-localds"
    fi
    
    # Check for wget or curl (at least one is required)
    if ! command -v wget &>/dev/null && ! command -v curl &>/dev/null; then
        missing_deps+=("wget or curl")
        print_debug "Missing: wget and curl"
    fi
    
    # Check for ISO creation tools (genisoimage or mkisofs)
    if ! command -v genisoimage &>/dev/null && ! command -v mkisofs &>/dev/null; then
        missing_deps+=("genisoimage or mkisofs")
        print_debug "Missing: genisoimage and mkisofs"
    fi
    
    # Check for openssl (used for password hashing)
    if ! command -v openssl &>/dev/null; then
        missing_deps+=("openssl")
        print_debug "Missing: openssl"
    fi
    
    # If there are missing dependencies, print error and exit
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        print_error "Missing required dependencies:"
        for dep in "${missing_deps[@]}"; do
            echo "  - ${dep}"
        done
        echo ""
        print_info "To install all required packages, run:"
        echo "  ${install_instructions}"
        echo ""
        exit 1
    fi
    
    print_success "All required dependencies are installed"
}

# ========================== DIRECTORY MANAGEMENT ==========================

# Create necessary directory structure for VM storage
setup_directories() {
    print_info "Setting up directory structure..."
    
    # Create base directories if they don't exist
    mkdir -p "${IMAGES_DIR}"
    mkdir -p "${VMS_DIR}"
    mkdir -p "${CONFIG_DIR}"
    
    print_success "Directories created at: ${VM_BASE_DIR}"
    print_debug "  Images: ${IMAGES_DIR}"
    print_debug "  VMs: ${VMS_DIR}"
    print_debug "  Configs: ${CONFIG_DIR}"
}

# ========================== IMAGE MANAGEMENT ==========================

# Display list of available cloud images
list_available_images() {
    echo ""
    echo -e "${BOLD}Available Cloud Images:${NC}"
    echo "------------------------"
    
    # Sort keys and display with numbers
    local i=1
    local sorted_keys
    sorted_keys=$(echo "${!CLOUD_IMAGES[@]}" | tr ' ' '\n' | sort)
    
    for key in ${sorted_keys}; do
        printf "  ${GREEN}%2d)${NC} %s\n" $i "$key"
        ((i++))
    done
    echo ""
}

# Get image name by selection number
get_image_by_number() {
    local num="$1"
    local sorted_keys
    sorted_keys=$(echo "${!CLOUD_IMAGES[@]}" | tr ' ' '\n' | sort)
    
    local i=1
    for key in ${sorted_keys}; do
        if [[ $i -eq $num ]]; then
            echo "$key"
            return 0
        fi
        ((i++))
    done
    return 1
}

# Download cloud image if not already present
download_cloud_image() {
    local image_name="$1"
    
    # Verify image exists in our list
    if [[ -z "${CLOUD_IMAGES[$image_name]:-}" ]]; then
        print_error "Unknown image: ${image_name}"
        return 1
    fi
    
    local image_url="${CLOUD_IMAGES[$image_name]}"
    local image_file="${IMAGES_DIR}/${image_name}.qcow2"
    
    # Check if already downloaded
    if [[ -f "${image_file}" ]]; then
        local file_size
        file_size=$(stat -c%s "${image_file}" 2>/dev/null || stat -f%z "${image_file}" 2>/dev/null || echo "0")
        if [[ ${file_size} -gt 100000000 ]]; then  # At least 100MB
            print_info "Cloud image '${image_name}' already exists ($(numfmt --to=iec ${file_size} 2>/dev/null || echo "${file_size} bytes"))"
            return 0
        else
            print_warning "Existing image file seems corrupt (too small), re-downloading..."
            rm -f "${image_file}"
        fi
    fi
    
    print_info "Downloading cloud image: ${image_name}"
    print_info "URL: ${image_url}"
    print_info "This may take a few minutes depending on your connection..."
    
    local tmp_file="${image_file}.downloading"
    
    # Download using wget or curl
    if command -v wget &>/dev/null; then
        if ! wget --progress=bar:force:noscroll -O "${tmp_file}" "${image_url}" 2>&1; then
            print_error "Download failed with wget"
            rm -f "${tmp_file}"
            return 1
        fi
    elif command -v curl &>/dev/null; then
        if ! curl -L --progress-bar -o "${tmp_file}" "${image_url}"; then
            print_error "Download failed with curl"
            rm -f "${tmp_file}"
            return 1
        fi
    fi
    
    # Verify download completed and file is not empty
    if [[ ! -s "${tmp_file}" ]]; then
        print_error "Downloaded file is empty or download failed"
        rm -f "${tmp_file}"
        return 1
    fi
    
    # Convert to qcow2 format (ensures consistent format)
    print_info "Converting image to qcow2 format..."
    if qemu-img convert -O qcow2 "${tmp_file}" "${image_file}" 2>/dev/null; then
        rm -f "${tmp_file}"
    else
        # If conversion fails, the file might already be qcow2
        mv "${tmp_file}" "${image_file}"
    fi
    
    local final_size
    final_size=$(stat -c%s "${image_file}" 2>/dev/null || stat -f%z "${image_file}" 2>/dev/null || echo "unknown")
    print_success "Cloud image downloaded: ${image_file} ($(numfmt --to=iec ${final_size} 2>/dev/null || echo "${final_size} bytes"))"
    return 0
}

# ========================== INPUT VALIDATION ==========================

# Validate VM name
validate_vm_name() {
    local name="$1"
    
    if [[ -z "${name}" ]]; then
        print_error "VM name cannot be empty"
        return 1
    fi
    
    # Must start with letter, contain only alphanumeric, hyphens, underscores
    if [[ ! "${name}" =~ ^[a-zA-Z][a-zA-Z0-9_-]*$ ]]; then
        print_error "VM name must start with a letter and contain only letters, numbers, hyphens, and underscores"
        return 1
    fi
    
    # Length check
    if [[ ${#name} -gt 64 ]]; then
        print_error "VM name must be 64 characters or less"
        return 1
    fi
    
    if [[ ${#name} -lt 2 ]]; then
        print_error "VM name must be at least 2 characters"
        return 1
    fi
    
    # Check if VM already exists
    if [[ -d "${VMS_DIR}/${name}" ]]; then
        print_error "VM '${name}' already exists"
        return 1
    fi
    
    return 0
}

# Validate hostname
validate_hostname() {
    local hostname="$1"
    
    if [[ -z "${hostname}" ]]; then
        print_error "Hostname cannot be empty"
        return 1
    fi
    
    # RFC 1123 hostname validation
    if [[ ! "${hostname}" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]]; then
        print_error "Invalid hostname. Must start/end with alphanumeric and contain only letters, numbers, and hyphens"
        return 1
    fi
    
    if [[ ${#hostname} -gt 63 ]]; then
        print_error "Hostname must be 63 characters or less"
        return 1
    fi
    
    return 0
}

# Validate SSH port number
validate_ssh_port() {
    local port="$1"
    
    # Must be numeric
    if [[ ! "${port}" =~ ^[0-9]+$ ]]; then
        print_error "SSH port must be a number"
        return 1
    fi
    
    # Valid port range
    if [[ ${port} -lt 1 ]] || [[ ${port} -gt 65535 ]]; then
        print_error "SSH port must be between 1 and 65535"
        return 1
    fi
    
    # Warning for privileged ports
    if [[ ${port} -lt 1024 ]] && [[ $EUID -ne 0 ]]; then
        print_warning "Port ${port} is a privileged port and requires root to bind"
    fi
    
    # Check against ports used in this session
    for used_port in "${USED_PORTS[@]}"; do
        if [[ "${used_port}" == "${port}" ]]; then
            print_error "SSH port ${port} is already selected for another VM in this session"
            return 1
        fi
    done
    
    # Check against existing VM configurations
    for config_file in "${CONFIG_DIR}"/*.conf 2>/dev/null; do
        if [[ -f "${config_file}" ]]; then
            local existing_port
            existing_port=$(grep "^SSH_PORT=" "${config_file}" 2>/dev/null | cut -d'=' -f2 | tr -d '"')
            if [[ "${existing_port}" == "${port}" ]]; then
                local existing_vm
                existing_vm=$(grep "^VM_NAME=" "${config_file}" 2>/dev/null | cut -d'=' -f2 | tr -d '"')
                print_error "SSH port ${port} is already used by VM '${existing_vm}'"
                return 1
            fi
        fi
    done
    
    # Check if port is in use on the host
    if command -v ss &>/dev/null; then
        if ss -tuln 2>/dev/null | grep -q ":${port} "; then
            print_warning "Port ${port} appears to be in use on this host"
        fi
    elif command -v netstat &>/dev/null; then
        if netstat -tuln 2>/dev/null | grep -q ":${port} "; then
            print_warning "Port ${port} appears to be in use on this host"
        fi
    fi
    
    return 0
}

# Validate Linux username
validate_username() {
    local username="$1"
    
    if [[ -z "${username}" ]]; then
        print_error "Username cannot be empty"
        return 1
    fi
    
    # Linux username rules: start with lowercase letter or underscore
    if [[ ! "${username}" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
        print_error "Username must start with a lowercase letter or underscore, and contain only lowercase letters, numbers, underscores, and hyphens"
        return 1
    fi
    
    # Length check
    if [[ ${#username} -gt 32 ]]; then
        print_error "Username must be 32 characters or less"
        return 1
    fi
    
    if [[ ${#username} -lt 1 ]]; then
        print_error "Username must be at least 1 character"
        return 1
    fi
    
    # Reserved system usernames that should not be used
    local reserved_users=(
        "root" "daemon" "bin" "sys" "sync" "games" "man" "lp" "mail" 
        "news" "uucp" "proxy" "www-data" "backup" "list" "irc" "gnats" 
        "nobody" "systemd-network" "systemd-resolve" "systemd-timesync"
        "messagebus" "syslog" "sshd" "ntp" "mysql" "postgres" "redis"
        "nginx" "apache" "http" "ftp" "git" "svn" "admin" "administrator"
        "guest" "operator" "adm" "lpadmin" "sambashare" "docker" "libvirt"
    )
    
    for reserved in "${reserved_users[@]}"; do
        if [[ "${username}" == "${reserved}" ]]; then
            print_error "Username '${username}' is a reserved system username"
            return 1
        fi
    done
    
    return 0
}

# Validate password
validate_password() {
    local password="$1"
    
    if [[ -z "${password}" ]]; then
        print_error "Password cannot be empty"
        return 1
    fi
    
    if [[ ${#password} -lt 6 ]]; then
        print_error "Password must be at least 6 characters long"
        return 1
    fi
    
    if [[ ${#password} -gt 128 ]]; then
        print_error "Password must be 128 characters or less"
        return 1
    fi
    
    return 0
}

# Validate RAM size specification
validate_ram() {
    local ram="$1"
    
    # Accept formats like: 512M, 2G, 2048M, 4G
    if [[ ! "${ram}" =~ ^[0-9]+[GgMm]?$ ]]; then
        print_error "Invalid RAM format. Use format like '2G', '2048M', or '512M'"
        return 1
    fi
    
    # Convert to MB for validation
    local ram_mb=0
    if [[ "${ram}" =~ [Gg]$ ]]; then
        ram_mb=$((${ram%[Gg]} * 1024))
    elif [[ "${ram}" =~ [Mm]$ ]]; then
        ram_mb=${ram%[Mm]}
    else
        ram_mb=${ram}
    fi
    
    if [[ ${ram_mb} -lt 256 ]]; then
        print_error "RAM must be at least 256M"
        return 1
    fi
    
    if [[ ${ram_mb} -gt 131072 ]]; then  # 128GB
        print_error "RAM cannot exceed 128G"
        return 1
    fi
    
    return 0
}

# Validate disk size specification
validate_disk() {
    local disk="$1"
    
    # Accept formats like: 10G, 100G, 1T
    if [[ ! "${disk}" =~ ^[0-9]+[GgTtMm]?$ ]]; then
        print_error "Invalid disk size format. Use format like '20G', '100G', or '1T'"
        return 1
    fi
    
    # Convert to GB for validation
    local disk_gb=0
    if [[ "${disk}" =~ [Tt]$ ]]; then
        disk_gb=$((${disk%[Tt]} * 1024))
    elif [[ "${disk}" =~ [Gg]$ ]]; then
        disk_gb=${disk%[Gg]}
    elif [[ "${disk}" =~ [Mm]$ ]]; then
        disk_gb=$((${disk%[Mm]} / 1024))
    else
        disk_gb=${disk}
    fi
    
    if [[ ${disk_gb} -lt 5 ]]; then
        print_error "Disk size must be at least 5G"
        return 1
    fi
    
    if [[ ${disk_gb} -gt 2048 ]]; then  # 2TB
        print_error "Disk size cannot exceed 2T"
        return 1
    fi
    
    return 0
}

# Validate vCPU count
validate_vcpus() {
    local vcpus="$1"
    
    if [[ ! "${vcpus}" =~ ^[0-9]+$ ]]; then
        print_error "vCPUs must be a number"
        return 1
    fi
    
    if [[ ${vcpus} -lt 1 ]]; then
        print_error "vCPUs must be at least 1"
        return 1
    fi
    
    if [[ ${vcpus} -gt 64 ]]; then
        print_error "vCPUs cannot exceed 64"
        return 1
    fi
    
    # Get host CPU count for warning
    local host_cpus
    host_cpus=$(nproc 2>/dev/null || echo "0")
    if [[ ${host_cpus} -gt 0 ]] && [[ ${vcpus} -gt ${host_cpus} ]]; then
        print_warning "Requested vCPUs (${vcpus}) exceeds host CPUs (${host_cpus})"
    fi
    
    return 0
}

# ========================== CLOUD-INIT GENERATION ==========================

# Generate cloud-init user-data configuration
generate_cloud_init_userdata() {
    local vm_dir="$1"
    local hostname="$2"
    local username="$3"
    local password="$4"
    
    print_info "Generating cloud-init configuration..."
    
    # Generate secure password hash using SHA-512
    local password_hash
    if command -v openssl &>/dev/null; then
        password_hash=$(openssl passwd -6 -stdin <<< "${password}" 2>/dev/null)
    fi
    
    # Fallback methods if openssl fails
    if [[ -z "${password_hash}" ]] && command -v python3 &>/dev/null; then
        password_hash=$(python3 -c "import crypt; print(crypt.crypt('${password}', crypt.mksalt(crypt.METHOD_SHA512)))" 2>/dev/null)
    fi
    
    if [[ -z "${password_hash}" ]] && command -v mkpasswd &>/dev/null; then
        password_hash=$(mkpasswd -m sha-512 "${password}" 2>/dev/null)
    fi
    
    # If all hashing methods fail, use plain text (less secure)
    if [[ -z "${password_hash}" ]]; then
        print_warning "Could not hash password, using plain text (less secure)"
        password_hash="${password}"
    fi
    
    # Create user-data file with cloud-init configuration
    cat > "${vm_dir}/user-data" << USERDATA_EOF
#cloud-config
# MEHRAZ VM Cloud-Init Configuration
# Generated: $(date -Iseconds)

# Set the hostname
hostname: ${hostname}
fqdn: ${hostname}.local
manage_etc_hosts: true
prefer_fqdn_over_hostname: false

# Create the non-root user with sudo privileges
users:
  - name: ${username}
    gecos: "${username} (created by mehraz VM manager)"
    groups: [sudo, adm, systemd-journal, users]
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
    shell: /bin/bash
    lock_passwd: false
    passwd: "${password_hash}"
    ssh_pwauth: true

# Configure password authentication
chpasswd:
  expire: false
  users:
    - name: root
      password: "${password_hash}"
      type: HASH
    - name: ${username}
      password: "${password_hash}"
      type: HASH

# Enable SSH password authentication
ssh_pwauth: true

# SSH server configuration
ssh:
  emit_keys_to_console: false

# Disable root SSH login via key but allow password
disable_root: false

# Timezone configuration (can be customized)
timezone: UTC

# Write custom configuration files
write_files:
  # Custom SSH configuration
  - path: /etc/ssh/sshd_config.d/99-mehraz-custom.conf
    content: |
      # MEHRAZ VM SSH Configuration
      PermitRootLogin yes
      PasswordAuthentication yes
      PubkeyAuthentication yes
      ChallengeResponseAuthentication no
      UsePAM yes
      X11Forwarding no
      PrintMotd yes
      AcceptEnv LANG LC_*
      Subsystem sftp /usr/lib/openssh/sftp-server
    permissions: '0644'
    owner: root:root

  # Custom MOTD banner
  - path: /etc/motd
    content: |
      
      ╔══════════════════════════════════════════════════════════════╗
      ║                    MEHRAZ Virtual Machine                    ║
      ║                                                              ║
      ║  Hostname: ${hostname}                                       
      ║  User: ${username}                                           
      ║                                                              ║
      ║  VM managed by MEHRAZ VM Manager                             ║
      ╚══════════════════════════════════════════════════════════════╝
      
    permissions: '0644'
    owner: root:root

  # VM info file
  - path: /etc/mehraz-vm-info
    content: |
      VM_HOSTNAME=${hostname}
      VM_USERNAME=${username}
      VM_CREATED=$(date -Iseconds)
      VM_MANAGER=mehraz
    permissions: '0644'
    owner: root:root

# Packages to install on first boot
package_update: true
package_upgrade: false
packages:
  - qemu-guest-agent
  - vim
  - curl
  - wget
  - htop
  - net-tools
  - sudo
  - openssh-server

# Commands to execute during first boot
runcmd:
  # Restart SSH service to apply configuration
  - systemctl restart sshd.service || systemctl restart ssh.service || true
  
  # Enable and start QEMU guest agent for host communication
  - systemctl enable qemu-guest-agent.service || true
  - systemctl start qemu-guest-agent.service || true
  
  # Ensure the user can use sudo without issues
  - usermod -aG sudo ${username} || usermod -aG wheel ${username} || true
  
  # Log successful initialization
  - echo "MEHRAZ VM '${hostname}' initialized successfully at \$(date)" >> /var/log/mehraz-init.log
  
  # Set proper permissions
  - chmod 700 /home/${username}/.ssh 2>/dev/null || true

# Power state configuration - do not reboot
power_state:
  delay: now
  mode: poweroff
  message: "Cloud-init completed, system configured"
  timeout: 30
  condition: false

# Final message to log
final_message: |
  MEHRAZ cloud-init completed for ${hostname}
  Version: \$version
  Datasource: \$datasource
  Uptime: \$uptime seconds
USERDATA_EOF

    # Create meta-data file (required by cloud-init)
    cat > "${vm_dir}/meta-data" << METADATA_EOF
instance-id: ${hostname}-$(date +%s%N | sha256sum | head -c 8)
local-hostname: ${hostname}
METADATA_EOF

    # Create network-config for DHCP on common interface names
    cat > "${vm_dir}/network-config" << NETWORK_EOF
version: 2
ethernets:
  id0:
    match:
      driver: virtio
    dhcp4: true
    dhcp6: false
  eth0:
    dhcp4: true
    dhcp6: false
    optional: true
  ens3:
    dhcp4: true
    dhcp6: false
    optional: true
  enp0s3:
    dhcp4: true
    dhcp6: false
    optional: true
NETWORK_EOF

    print_success "Cloud-init configuration generated"
}

# Create cloud-init ISO image for VM boot
create_cloud_init_iso() {
    local vm_dir="$1"
    local iso_file="${vm_dir}/cloud-init.iso"
    
    print_info "Creating cloud-init ISO image..."
    
    # Remove existing ISO if present
    rm -f "${iso_file}"
    
    # Try cloud-localds first (preferred method)
    if command -v cloud-localds &>/dev/null; then
        if cloud-localds -N "${vm_dir}/network-config" "${iso_file}" "${vm_dir}/user-data" "${vm_dir}/meta-data" 2>/dev/null; then
            print_success "Cloud-init ISO created using cloud-localds"
            return 0
        fi
        # Fallback without network config
        if cloud-localds "${iso_file}" "${vm_dir}/user-data" "${vm_dir}/meta-data" 2>/dev/null; then
            print_success "Cloud-init ISO created using cloud-localds (no network config)"
            return 0
        fi
    fi
    
    # Fallback to genisoimage
    if command -v genisoimage &>/dev/null; then
        if genisoimage -output "${iso_file}" -volid cidata -joliet -rock \
            "${vm_dir}/user-data" "${vm_dir}/meta-data" "${vm_dir}/network-config" 2>/dev/null; then
            print_success "Cloud-init ISO created using genisoimage"
            return 0
        fi
    fi
    
    # Fallback to mkisofs
    if command -v mkisofs &>/dev/null; then
        if mkisofs -output "${iso_file}" -volid cidata -joliet -rock \
            "${vm_dir}/user-data" "${vm_dir}/meta-data" "${vm_dir}/network-config" 2>/dev/null; then
            print_success "Cloud-init ISO created using mkisofs"
            return 0
        fi
    fi
    
    print_error "Failed to create cloud-init ISO. No suitable tool available."
    return 1
}

# ========================== VM CREATION ==========================

# Create VM disk from cloud image template
create_vm_disk() {
    local vm_name="$1"
    local image_name="$2"
    local disk_size="$3"
    
    local vm_dir="${VMS_DIR}/${vm_name}"
    local base_image="${IMAGES_DIR}/${image_name}.qcow2"
    local vm_disk="${vm_dir}/${vm_name}.qcow2"
    
    print_info "Creating VM disk with backing file..."
    
    # Verify base image exists
    if [[ ! -f "${base_image}" ]]; then
        print_error "Base image not found: ${base_image}"
        return 1
    fi
    
    # Create qcow2 disk with backing file (copy-on-write)
    if ! qemu-img create -f qcow2 -F qcow2 -b "${base_image}" "${vm_disk}" "${disk_size}"; then
        print_error "Failed to create VM disk"
        return 1
    fi
    
    print_success "VM disk created: ${vm_disk} (${disk_size}, backed by ${image_name})"
    return 0
}

# Save VM configuration to file
save_vm_config() {
    local vm_name="$1"
    local hostname="$2"
    local ssh_port="$3"
    local username="$4"
    local ram="$5"
    local vcpus="$6"
    local disk_size="$7"
    local image_name="$8"
    
    local config_file="${CONFIG_DIR}/${vm_name}.conf"
    local vm_dir="${VMS_DIR}/${vm_name}"
    
    cat > "${config_file}" << CONFIG_EOF
# MEHRAZ VM Configuration File
# Generated: $(date -Iseconds)
# Do not edit manually unless you know what you're doing

# VM Identity
VM_NAME="${vm_name}"
HOSTNAME="${hostname}"
USERNAME="${username}"

# Network Configuration
SSH_PORT="${ssh_port}"

# Resource Allocation
RAM="${ram}"
VCPUS="${vcpus}"
DISK_SIZE="${disk_size}"

# Image Information
IMAGE="${image_name}"

# Paths
VM_DIR="${vm_dir}"
VM_DISK="${vm_dir}/${vm_name}.qcow2"
CLOUD_INIT_ISO="${vm_dir}/cloud-init.iso"
PID_FILE="${vm_dir}/${vm_name}.pid"
MONITOR_SOCKET="${vm_dir}/monitor.sock"
CONFIG_EOF

    chmod 600 "${config_file}"
    print_success "Configuration saved: ${config_file}"
}

# Generate VM start script
generate_vm_start_script() {
    local vm_name="$1"
    local hostname="$2"
    local ssh_port="$3"
    local username="$4"
    local ram="$5"
    local vcpus="$6"
    
    local vm_dir="${VMS_DIR}/${vm_name}"
    local script_file="${vm_dir}/start.sh"
    
    cat > "${script_file}" << 'START_SCRIPT_HEADER'
#!/bin/bash
# MEHRAZ VM Start Script
# Auto-generated - modifications may be overwritten

set -euo pipefail

START_SCRIPT_HEADER

    cat >> "${script_file}" << START_SCRIPT_VARS
# VM Configuration
VM_NAME="${vm_name}"
HOSTNAME="${hostname}"
SSH_PORT="${ssh_port}"
USERNAME="${username}"
RAM="${ram}"
VCPUS="${vcpus}"

# Paths
VM_DIR="${vm_dir}"
VM_DISK="${vm_dir}/${vm_name}.qcow2"
CLOUD_INIT_ISO="${vm_dir}/cloud-init.iso"
PID_FILE="${vm_dir}/${vm_name}.pid"
MONITOR_SOCKET="${vm_dir}/monitor.sock"
LOG_FILE="${vm_dir}/${vm_name}.log"

START_SCRIPT_VARS

    cat >> "${script_file}" << 'START_SCRIPT_BODY'
# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}Starting MEHRAZ VM: ${VM_NAME}${NC}"
echo "========================================"

# Check if VM is already running
if [[ -f "${PID_FILE}" ]]; then
    OLD_PID=$(cat "${PID_FILE}")
    if kill -0 "${OLD_PID}" 2>/dev/null; then
        echo -e "${YELLOW}VM is already running (PID: ${OLD_PID})${NC}"
        echo ""
        echo "SSH Connection:"
        echo "  ssh -p ${SSH_PORT} ${USERNAME}@localhost"
        echo ""
        echo "To stop the VM, run: ${VM_DIR}/stop.sh"
        exit 0
    else
        echo "Removing stale PID file..."
        rm -f "${PID_FILE}"
    fi
fi

# Verify required files exist
if [[ ! -f "${VM_DISK}" ]]; then
    echo -e "${RED}Error: VM disk not found: ${VM_DISK}${NC}"
    exit 1
fi

if [[ ! -f "${CLOUD_INIT_ISO}" ]]; then
    echo -e "${RED}Error: Cloud-init ISO not found: ${CLOUD_INIT_ISO}${NC}"
    exit 1
fi

# Clean up old socket
rm -f "${MONITOR_SOCKET}"

echo "Configuration:"
echo "  Hostname: ${HOSTNAME}"
echo "  SSH Port: ${SSH_PORT}"
echo "  Username: ${USERNAME}"
echo "  RAM: ${RAM}"
echo "  vCPUs: ${VCPUS}"
echo ""

# Start the VM with QEMU
echo "Starting QEMU virtual machine..."

qemu-system-x86_64 \
    -name "${VM_NAME},process=${VM_NAME}" \
    -machine type=q35,accel=kvm \
    -cpu host \
    -smp "${VCPUS}",sockets=1,cores="${VCPUS}",threads=1 \
    -m "${RAM}" \
    -drive file="${VM_DISK}",format=qcow2,if=virtio,cache=writeback \
    -drive file="${CLOUD_INIT_ISO}",format=raw,if=virtio,readonly=on \
    -netdev user,id=net0,hostfwd=tcp::${SSH_PORT}-:22 \
    -device virtio-net-pci,netdev=net0,mac=$(printf '52:54:00:%02x:%02x:%02x' $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256))) \
    -device virtio-balloon-pci,id=balloon0 \
    -object rng-random,id=rng0,filename=/dev/urandom \
    -device virtio-rng-pci,rng=rng0 \
    -chardev socket,id=qga0,path="${VM_DIR}/qga.sock",server=on,wait=off \
    -device virtio-serial-pci \
    -device virtserialport,chardev=qga0,name=org.qemu.guest_agent.0 \
    -monitor unix:"${MONITOR_SOCKET}",server,nowait \
    -pidfile "${PID_FILE}" \
    -nographic \
    -serial mon:stdio \
    >> "${LOG_FILE}" 2>&1 &

QEMU_PID=$!

# Wait briefly and verify VM started
sleep 3

if [[ -f "${PID_FILE}" ]]; then
    SAVED_PID=$(cat "${PID_FILE}")
    if kill -0 "${SAVED_PID}" 2>/dev/null; then
        echo -e "${GREEN}VM started successfully!${NC}"
        echo ""
        echo "Process ID: ${SAVED_PID}"
        echo "Log file: ${LOG_FILE}"
        echo ""
        echo "========================================"
        echo -e "${GREEN}SSH Connection (wait ~60-90 seconds for boot):${NC}"
        echo "  ssh -p ${SSH_PORT} ${USERNAME}@localhost"
        echo ""
        echo "To stop the VM:"
        echo "  ${VM_DIR}/stop.sh"
        echo ""
        echo "To view console output:"
        echo "  tail -f ${LOG_FILE}"
        echo "========================================"
    else
        echo -e "${RED}VM process exited unexpectedly${NC}"
        echo "Check log file: ${LOG_FILE}"
        rm -f "${PID_FILE}"
        exit 1
    fi
else
    echo -e "${RED}Failed to start VM - no PID file created${NC}"
    echo "Check log file: ${LOG_FILE}"
    exit 1
fi
START_SCRIPT_BODY

    chmod +x "${script_file}"
    print_debug "Start script generated: ${script_file}"
}

# Generate VM stop script
generate_vm_stop_script() {
    local vm_name="$1"
    local vm_dir="${VMS_DIR}/${vm_name}"
    local script_file="${vm_dir}/stop.sh"
    
    cat > "${script_file}" << STOP_SCRIPT
#!/bin/bash
# MEHRAZ VM Stop Script
# Auto-generated - modifications may be overwritten

set -euo pipefail

VM_NAME="${vm_name}"
VM_DIR="${vm_dir}"
PID_FILE="${vm_dir}/${vm_name}.pid"
MONITOR_SOCKET="${vm_dir}/monitor.sock"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "\${GREEN}Stopping MEHRAZ VM: \${VM_NAME}\${NC}"

# Check if PID file exists
if [[ ! -f "\${PID_FILE}" ]]; then
    echo -e "\${YELLOW}VM does not appear to be running (no PID file)\${NC}"
    exit 0
fi

PID=\$(cat "\${PID_FILE}")

# Check if process is running
if ! kill -0 "\${PID}" 2>/dev/null; then
    echo -e "\${YELLOW}VM is not running (stale PID file)\${NC}"
    rm -f "\${PID_FILE}"
    exit 0
fi

echo "VM is running with PID: \${PID}"
echo ""

# Try graceful shutdown via QEMU monitor
if [[ -S "\${MONITOR_SOCKET}" ]]; then
    echo "Attempting graceful shutdown via QEMU monitor..."
    if command -v socat &>/dev/null; then
        echo "system_powerdown" | socat - UNIX-CONNECT:"\${MONITOR_SOCKET}" 2>/dev/null || true
    else
        echo "system_powerdown" | nc -U "\${MONITOR_SOCKET}" 2>/dev/null || true
    fi
    
    # Wait for graceful shutdown (up to 30 seconds)
    echo "Waiting for graceful shutdown (up to 30 seconds)..."
    for i in {1..30}; do
        if ! kill -0 "\${PID}" 2>/dev/null; then
            echo -e "\${GREEN}VM shut down gracefully\${NC}"
            rm -f "\${PID_FILE}"
            rm -f "\${MONITOR_SOCKET}"
            exit 0
        fi
        sleep 1
        echo -n "."
    done
    echo ""
fi

# Graceful shutdown didn't work, try SIGTERM
echo -e "\${YELLOW}Graceful shutdown failed, sending SIGTERM...\${NC}"
kill "\${PID}" 2>/dev/null || true

# Wait for SIGTERM (up to 10 seconds)
for i in {1..10}; do
    if ! kill -0 "\${PID}" 2>/dev/null; then
        echo -e "\${GREEN}VM stopped with SIGTERM\${NC}"
        rm -f "\${PID_FILE}"
        rm -f "\${MONITOR_SOCKET}"
        exit 0
    fi
    sleep 1
done

# Force kill with SIGKILL
echo -e "\${RED}SIGTERM failed, sending SIGKILL...\${NC}"
kill -9 "\${PID}" 2>/dev/null || true

sleep 1

if ! kill -0 "\${PID}" 2>/dev/null; then
    echo -e "\${GREEN}VM forcefully stopped\${NC}"
else
    echo -e "\${RED}Failed to stop VM\${NC}"
    exit 1
fi

rm -f "\${PID_FILE}"
rm -f "\${MONITOR_SOCKET}"
STOP_SCRIPT

    chmod +x "${script_file}"
    print_debug "Stop script generated: ${script_file}"
}

# Generate VM status script
generate_vm_status_script() {
    local vm_name="$1"
    local hostname="$2"
    local ssh_port="$3"
    local username="$4"
    local vm_dir="${VMS_DIR}/${vm_name}"
    local script_file="${vm_dir}/status.sh"
    
    cat > "${script_file}" << STATUS_SCRIPT
#!/bin/bash
# MEHRAZ VM Status Script
# Auto-generated - modifications may be overwritten

VM_NAME="${vm_name}"
HOSTNAME="${hostname}"
SSH_PORT="${ssh_port}"
USERNAME="${username}"
VM_DIR="${vm_dir}"
PID_FILE="${vm_dir}/${vm_name}.pid"
VM_DISK="${vm_dir}/${vm_name}.qcow2"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "\${CYAN}MEHRAZ VM Status: \${VM_NAME}\${NC}"
echo "========================================"
echo ""
echo "Configuration:"
echo "  Hostname:  \${HOSTNAME}"
echo "  Username:  \${USERNAME}"
echo "  SSH Port:  \${SSH_PORT}"
echo "  Directory: \${VM_DIR}"
echo ""

# Get disk size
if [[ -f "\${VM_DISK}" ]]; then
    DISK_SIZE=\$(qemu-img info "\${VM_DISK}" 2>/dev/null | grep 'virtual size' | awk '{print \$3, \$4}' || echo "unknown")
    echo "Disk: \${DISK_SIZE}"
fi

echo ""

# Check running status
if [[ -f "\${PID_FILE}" ]]; then
    PID=\$(cat "\${PID_FILE}")
    if kill -0 "\${PID}" 2>/dev/null; then
        echo -e "Status: \${GREEN}RUNNING\${NC} (PID: \${PID})"
        echo ""
        echo "SSH Command:"
        echo "  ssh -p \${SSH_PORT} \${USERNAME}@localhost"
    else
        echo -e "Status: \${RED}STOPPED\${NC} (stale PID file)"
    fi
else
    echo -e "Status: 
