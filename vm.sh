#!/bin/bash
set -euo pipefail

# =============================
# Enhanced Multi-VM Manager v2.3 (Improved)
# Fixed: Password authentication, user creation, error handling
# =============================

# Global variables
VERSION="2.3"
KVM_AVAILABLE=true
QEMU_CMD=()

# Function to display header
display_header() {
    clear
    cat << "EOF"
========================================================================
  __  __ ______ _    _ _____            ______
 |  \/  |  ____| |  | |  __ \     /\   |___  /
 | \  / | |__  | |__| | |__) |   /  \     / /
 | |\/| |  __| |  __  |  _  /   / /\ \   / /
 | |  | | |____| |  | | | \ \  / ____ \ / /__
 |_|  |_|______|_|  |_|_|  \_\/_/    \_\_____|

                 ONLY ALLAH CAN HELP US
========================================================================
EOF
    echo "                      VM Manager v$VERSION"
    echo "========================================================================"
    echo
}

# Function to display colored output
print_status() {
    local type=$1
    local message=$2

    case $type in
        "INFO")    echo -e "\033[1;34m[INFO]\033[0m $message" ;;
        "WARN")    echo -e "\033[1;33m[WARN]\033[0m $message" ;;
        "ERROR")   echo -e "\033[1;31m[ERROR]\033[0m $message" ;;
        "SUCCESS") echo -e "\033[1;32m[SUCCESS]\033[0m $message" ;;
        "INPUT")   echo -e "\033[1;36m[INPUT]\033[0m $message" ;;
        "DEBUG")   echo -e "\033[1;35m[DEBUG]\033[0m $message" ;;
        *)         echo "[$type] $message" ;;
    esac
}

# Function to validate input - IMPROVED
validate_input() {
    local type=$1
    local value=$2

    case $type in
        "number")
            if ! [[ "$value" =~ ^[0-9]+$ ]]; then
                print_status "ERROR" "Must be a number"
                return 1
            fi
            if [ "$value" -eq 0 ]; then
                print_status "ERROR" "Must be greater than 0"
                return 1
            fi
            ;;
        "size")
            if ! [[ "$value" =~ ^[0-9]+[GgMm]$ ]]; then
                print_status "ERROR" "Must be a size with unit (e.g., 100G, 512M)"
                return 1
            fi
            ;;
        "port")
            if ! [[ "$value" =~ ^[0-9]+$ ]] || [ "$value" -lt 1024 ] || [ "$value" -gt 65535 ]; then
                print_status "ERROR" "Must be a valid port number (1024-65535)"
                return 1
            fi
            ;;
        "name")
            if ! [[ "$value" =~ ^[a-zA-Z0-9_-]+$ ]]; then
                print_status "ERROR" "Name can only contain letters, numbers, hyphens, and underscores"
                return 1
            fi
            if [ ${#value} -gt 64 ]; then
                print_status "ERROR" "Name must be 64 characters or less"
                return 1
            fi
            ;;
        "username")
            # FIXED: More permissive username validation
            if ! [[ "$value" =~ ^[a-z][a-z0-9_-]*$ ]]; then
                print_status "ERROR" "Username must start with lowercase letter, can contain lowercase letters, numbers, hyphens, underscores"
                return 1
            fi
            if [ ${#value} -gt 32 ]; then
                print_status "ERROR" "Username must be 32 characters or less"
                return 1
            fi
            if [ ${#value} -lt 1 ]; then
                print_status "ERROR" "Username cannot be empty"
                return 1
            fi
            ;;
        "password")
            if [ ${#value} -lt 1 ]; then
                print_status "ERROR" "Password cannot be empty"
                return 1
            fi
            ;;
    esac
    return 0
}

# Function to check KVM availability
check_kvm() {
    if [[ -e /dev/kvm ]]; then
        if [[ -r /dev/kvm ]] && [[ -w /dev/kvm ]]; then
            KVM_AVAILABLE=true
            print_status "SUCCESS" "KVM acceleration available"
        else
            KVM_AVAILABLE=false
            print_status "WARN" "KVM exists but no permission. Run: sudo usermod -aG kvm $USER"
        fi
    else
        KVM_AVAILABLE=false
        print_status "WARN" "KVM not available - VMs will run slower (software emulation)"
    fi
}

# Function to check dependencies
check_dependencies() {
    local deps=("qemu-system-x86_64" "wget" "qemu-img")
    local optional_deps=("cloud-localds" "openssl" "mkpasswd")
    local missing_deps=()
    local missing_optional=()

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done

    for dep in "${optional_deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_optional+=("$dep")
        fi
    done

    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_status "ERROR" "Missing required dependencies: ${missing_deps[*]}"
        echo
        print_status "INFO" "Install on Ubuntu/Debian:"
        echo "  sudo apt update && sudo apt install -y qemu-system-x86 qemu-utils cloud-image-utils wget openssl whois"
        echo
        print_status "INFO" "Install on Fedora/CentOS/RHEL:"
        echo "  sudo dnf install -y qemu-kvm qemu-img cloud-utils-growpart wget openssl"
        echo
        print_status "INFO" "Install on Arch Linux:"
        echo "  sudo pacman -S qemu-full cloud-utils wget openssl"
        exit 1
    fi

    if [ ${#missing_optional[@]} -ne 0 ]; then
        print_status "WARN" "Missing optional dependencies: ${missing_optional[*]}"
        print_status "INFO" "Some features may be limited"
    fi

    print_status "SUCCESS" "All required dependencies are installed"
}

# Function to cleanup temporary files
cleanup() {
    local temp_files=("user-data" "meta-data" "network-config")
    for file in "${temp_files[@]}"; do
        [[ -f "$file" ]] && rm -f "$file"
    done
}

# Function to check if port is available
is_port_available() {
    local port=$1
    if command -v ss &> /dev/null; then
        ! ss -tuln 2>/dev/null | grep -q ":$port "
    elif command -v netstat &> /dev/null; then
        ! netstat -tuln 2>/dev/null | grep -q ":$port "
    else
        return 0
    fi
}

# Function to find next available port
find_available_port() {
    local start_port=${1:-2222}
    local port=$start_port

    while ! is_port_available "$port" && [ "$port" -lt 65535 ]; do
        ((port++))
    done

    echo "$port"
}

# Function to get all VM configurations
get_vm_list() {
    if [[ -d "$VM_DIR" ]]; then
        find "$VM_DIR" -maxdepth 1 -name "*.conf" -type f 2>/dev/null | while read -r f; do
            basename "$f" .conf
        done | sort
    fi
}

# Function to load VM configuration
load_vm_config() {
    local vm_name=$1
    local config_file="$VM_DIR/$vm_name.conf"

    if [[ -f "$config_file" ]]; then
        # Clear previous variables
        VM_NAME=""
        OS_TYPE=""
        OS_VERSION=""
        CODENAME=""
        IMG_URL=""
        HOSTNAME=""
        USERNAME=""
        PASSWORD=""
        DISK_SIZE=""
        MEMORY=""
        CPUS=""
        SSH_PORT=""
        GUI_MODE=""
        PORT_FORWARDS=""
        IMG_FILE=""
        SEED_FILE=""
        CREATED=""

        # shellcheck source=/dev/null
        source "$config_file"
        return 0
    else
        print_status "ERROR" "Configuration for VM '$vm_name' not found"
        return 1
    fi
}

# Function to save VM configuration
save_vm_config() {
    local config_file="$VM_DIR/$VM_NAME.conf"

    cat > "$config_file" <<EOF
# VM Configuration - Generated by Mehraz VM Manager
# Created: $CREATED
# Last Modified: $(date)

VM_NAME="$VM_NAME"
OS_TYPE="$OS_TYPE"
OS_VERSION="$OS_VERSION"
CODENAME="$CODENAME"
IMG_URL="$IMG_URL"
HOSTNAME="$HOSTNAME"
USERNAME="$USERNAME"
PASSWORD="$PASSWORD"
DISK_SIZE="$DISK_SIZE"
MEMORY="$MEMORY"
CPUS="$CPUS"
SSH_PORT="$SSH_PORT"
GUI_MODE="$GUI_MODE"
PORT_FORWARDS="$PORT_FORWARDS"
IMG_FILE="$IMG_FILE"
SEED_FILE="$SEED_FILE"
CREATED="$CREATED"
EOF

    chmod 600 "$config_file"
    print_status "SUCCESS" "Configuration saved to $config_file"
}

# Function to detect image format
detect_image_format() {
    local img_file=$1
    local format
    format=$(qemu-img info "$img_file" 2>/dev/null | grep "file format:" | awk '{print $3}')
    echo "${format:-qcow2}"
}

# Function to download image with progress
download_image() {
    local url=$1
    local output=$2

    print_status "INFO" "Downloading image..."
    print_status "INFO" "URL: $url"
    echo

    local wget_opts=("--progress=bar:force:noscroll" "-O" "$output.tmp")
    wget_opts+=("--timeout=60" "--tries=3" "--continue")

    if wget "${wget_opts[@]}" "$url" 2>&1; then
        mv "$output.tmp" "$output"
        print_status "SUCCESS" "Download completed"
        return 0
    else
        rm -f "$output.tmp"
        print_status "ERROR" "Download failed"
        return 1
    fi
}

# IMPROVED: Robust password hash generation
generate_password_hash() {
    local password=$1
    local hash=""

    # Method 1: Try mkpasswd (most reliable)
    if command -v mkpasswd &> /dev/null; then
        hash=$(mkpasswd -m sha-512 "$password" 2>/dev/null) && [[ -n "$hash" ]] && echo "$hash" && return 0
    fi

    # Method 2: Try openssl with SHA-512
    if command -v openssl &> /dev/null; then
        # Generate a random salt
        local salt
        salt=$(openssl rand -base64 12 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c 16)
        if [[ -n "$salt" ]]; then
            hash=$(openssl passwd -6 -salt "$salt" "$password" 2>/dev/null)
            [[ -n "$hash" ]] && echo "$hash" && return 0
        fi

        # Fallback to MD5 if SHA-512 not supported
        hash=$(openssl passwd -1 "$password" 2>/dev/null)
        [[ -n "$hash" ]] && echo "$hash" && return 0
    fi

    # Method 3: Try Python
    if command -v python3 &> /dev/null; then
        hash=$(python3 -c "
import crypt
import secrets
salt = crypt.mksalt(crypt.METHOD_SHA512)
print(crypt.crypt('$password', salt))
" 2>/dev/null)
        [[ -n "$hash" ]] && echo "$hash" && return 0
    fi

    # Method 4: Try perl
    if command -v perl &> /dev/null; then
        hash=$(perl -e "print crypt('$password', '\$6\$' . join('', map { ('a'..'z', 'A'..'Z', '0'..'9')[rand 62] } 1..16) . '\$')" 2>/dev/null)
        [[ -n "$hash" ]] && echo "$hash" && return 0
    fi

    # If all else fails, return empty (will use plain password fallback)
    echo ""
}

# Function to create cloud-init ISO
create_cloud_init_iso() {
    local user_data_file=$1
    local meta_data_file=$2
    local output_iso=$3

    if command -v cloud-localds &> /dev/null; then
        cloud-localds "$output_iso" "$user_data_file" "$meta_data_file" 2>/dev/null
        return $?
    elif command -v genisoimage &> /dev/null; then
        genisoimage -output "$output_iso" -volid cidata -joliet -rock "$user_data_file" "$meta_data_file" 2>/dev/null
        return $?
    elif command -v mkisofs &> /dev/null; then
        mkisofs -output "$output_iso" -volid cidata -joliet -rock "$user_data_file" "$meta_data_file" 2>/dev/null
        return $?
    elif command -v xorriso &> /dev/null; then
        xorriso -as mkisofs -o "$output_iso" -V cidata -J -r "$user_data_file" "$meta_data_file" 2>/dev/null
        return $?
    else
        print_status "ERROR" "No tool available to create cloud-init ISO"
        print_status "INFO" "Install cloud-image-utils, genisoimage, or xorriso"
        return 1
    fi
}

# Function to create new VM
create_new_vm() {
    print_status "INFO" "Creating a new VM"
    echo

    # OS Selection
    print_status "INFO" "Select an OS:"
    echo

    local os_keys=()
    local i=1

    while IFS= read -r os; do
        os_keys+=("$os")
        printf "  %2d) %s\n" "$i" "$os"
        ((i++))
    done < <(printf '%s\n' "${!OS_OPTIONS[@]}" | sort)

    echo

    local os_count=${#os_keys[@]}
    while true; do
        read -p "$(print_status "INPUT" "Enter your choice (1-$os_count): ")" choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "$os_count" ]; then
            local os="${os_keys[$((choice-1))]}"
            IFS='|' read -r OS_TYPE OS_VERSION CODENAME IMG_URL DEFAULT_HOSTNAME DEFAULT_USERNAME DEFAULT_PASSWORD <<< "${OS_OPTIONS[$os]}"
            print_status "SUCCESS" "Selected: $os"
            break
        else
            print_status "ERROR" "Invalid selection. Try again."
        fi
    done

    echo

    # VM Name
    while true; do
        read -p "$(print_status "INPUT" "Enter VM name (default: $DEFAULT_HOSTNAME): ")" VM_NAME
        VM_NAME="${VM_NAME:-$DEFAULT_HOSTNAME}"
        if validate_input "name" "$VM_NAME"; then
            if [[ -f "$VM_DIR/$VM_NAME.conf" ]]; then
                print_status "ERROR" "VM with name '$VM_NAME' already exists"
            else
                break
            fi
        fi
    done

    # Hostname
    while true; do
        read -p "$(print_status "INPUT" "Enter hostname (default: $VM_NAME): ")" HOSTNAME
        HOSTNAME="${HOSTNAME:-$VM_NAME}"
        if validate_input "name" "$HOSTNAME"; then
            break
        fi
    done

    # Username - IMPROVED validation message
    while true; do
        read -p "$(print_status "INPUT" "Enter username (default: $DEFAULT_USERNAME): ")" USERNAME
        USERNAME="${USERNAME:-$DEFAULT_USERNAME}"
        if validate_input "username" "$USERNAME"; then
            break
        fi
    done

    # Password - IMPROVED: Skip confirmation if using default
    while true; do
        read -s -p "$(print_status "INPUT" "Enter password (default: $DEFAULT_PASSWORD): ")" PASSWORD
        echo
        if [[ -z "$PASSWORD" ]]; then
            PASSWORD="$DEFAULT_PASSWORD"
            print_status "INFO" "Using default password: $PASSWORD"
            break
        fi
        if validate_input "password" "$PASSWORD"; then
            read -s -p "$(print_status "INPUT" "Confirm password: ")" PASSWORD_CONFIRM
            echo
            if [ "$PASSWORD" = "$PASSWORD_CONFIRM" ]; then
                break
            else
                print_status "ERROR" "Passwords do not match"
            fi
        fi
    done

    # Disk Size
    while true; do
        read -p "$(print_status "INPUT" "Disk size (default: 20G): ")" DISK_SIZE
        DISK_SIZE="${DISK_SIZE:-20G}"
        if validate_input "size" "$DISK_SIZE"; then
            break
        fi
    done

    # Memory
    while true; do
        read -p "$(print_status "INPUT" "Memory in MB (default: 2048): ")" MEMORY
        MEMORY="${MEMORY:-2048}"
        if validate_input "number" "$MEMORY"; then
            if [ "$MEMORY" -lt 256 ]; then
                print_status "WARN" "Less than 256MB RAM may cause boot issues"
            fi
            break
        fi
    done

    # CPUs - NO LIMIT
    while true; do
        read -p "$(print_status "INPUT" "Number of CPUs (default: 2): ")" CPUS
        CPUS="${CPUS:-2}"
        if validate_input "number" "$CPUS"; then
            local host_cpus
            host_cpus=$(nproc 2>/dev/null || echo "unknown")
            if [[ "$host_cpus" != "unknown" ]] && [ "$CPUS" -gt "$host_cpus" ]; then
                print_status "INFO" "Note: Host has $host_cpus CPUs, VM will have $CPUS vCPUs"
            fi
            break
        fi
    done

    # SSH Port
    local suggested_port
    suggested_port=$(find_available_port 2222)
    while true; do
        read -p "$(print_status "INPUT" "SSH Port (default: $suggested_port): ")" SSH_PORT
        SSH_PORT="${SSH_PORT:-$suggested_port}"
        if validate_input "port" "$SSH_PORT"; then
            if ! is_port_available "$SSH_PORT"; then
                print_status "ERROR" "Port $SSH_PORT is already in use"
            else
                break
            fi
        fi
    done

    # GUI Mode
    while true; do
        read -p "$(print_status "INPUT" "Enable GUI mode? (y/n, default: n): ")" gui_input
        gui_input="${gui_input:-n}"
        if [[ "$gui_input" =~ ^[Yy]$ ]]; then
            GUI_MODE=true
            break
        elif [[ "$gui_input" =~ ^[Nn]$ ]]; then
            GUI_MODE=false
            break
        else
            print_status "ERROR" "Please answer y or n"
        fi
    done

    # Additional port forwards
    echo
    print_status "INFO" "Port forwarding format: host_port:guest_port (e.g., 8080:80,3000:3000)"
    read -p "$(print_status "INPUT" "Additional port forwards (press Enter for none): ")" PORT_FORWARDS
    PORT_FORWARDS="${PORT_FORWARDS:-}"

    # Set file paths
    IMG_FILE="$VM_DIR/$VM_NAME.qcow2"
    SEED_FILE="$VM_DIR/$VM_NAME-seed.iso"
    CREATED="$(date '+%Y-%m-%d %H:%M:%S')"

    echo
    print_status "INFO" "VM Configuration Summary:"
    echo "════════════════════════════════════════════"
    echo "  Name      : $VM_NAME"
    echo "  OS        : $OS_TYPE $OS_VERSION ($CODENAME)"
    echo "  Hostname  : $HOSTNAME"
    echo "  Username  : $USERNAME"
    echo "  Password  : $PASSWORD"
    echo "  Disk      : $DISK_SIZE"
    echo "  RAM       : ${MEMORY}MB"
    echo "  CPUs      : $CPUS"
    echo "  SSH Port  : $SSH_PORT"
    echo "  GUI Mode  : $GUI_MODE"
    echo "  Forwards  : ${PORT_FORWARDS:-None}"
    echo "════════════════════════════════════════════"
    echo

    read -p "$(print_status "INPUT" "Proceed with creation? (Y/n): ")" confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        print_status "INFO" "VM creation cancelled"
        return 1
    fi

    # Download and setup VM image
    if ! setup_vm_image; then
        print_status "ERROR" "Failed to setup VM image"
        return 1
    fi

    # Save configuration
    save_vm_config

    echo
    print_status "SUCCESS" "VM '$VM_NAME' created successfully!"
    print_status "INFO" "Start it with option 2 from the main menu"
}

# IMPROVED: Setup VM image with better cloud-init
setup_vm_image() {
    print_status "INFO" "Setting up VM image..."

    # Create VM directory if it doesn't exist
    mkdir -p "$VM_DIR"

    # Create base images directory
    local base_dir="$VM_DIR/.base-images"
    mkdir -p "$base_dir"

    # Download base image if needed
    local base_img="$base_dir/${OS_TYPE}-${CODENAME}.img"

    if [[ ! -f "$base_img" ]]; then
        if ! download_image "$IMG_URL" "$base_img"; then
            print_status "ERROR" "Failed to download base image"
            return 1
        fi
    else
        print_status "INFO" "Using cached base image"
    fi

    # Detect format of downloaded image
    local img_format
    img_format=$(detect_image_format "$base_img")

    print_status "INFO" "Base image format: $img_format"
    print_status "INFO" "Creating VM disk..."

    # Remove existing disk if exists
    [[ -f "$IMG_FILE" ]] && rm -f "$IMG_FILE"

    # Create overlay disk with backing file
    if qemu-img create -f qcow2 -F "$img_format" -b "$base_img" "$IMG_FILE" "$DISK_SIZE" 2>/dev/null; then
        print_status "SUCCESS" "Created overlay disk with backing file"
    else
        # Fallback: copy and resize
        print_status "INFO" "Using fallback method (full copy)..."
        if ! cp "$base_img" "$IMG_FILE"; then
            print_status "ERROR" "Failed to copy base image"
            return 1
        fi

        # Convert to qcow2 if needed
        if [[ "$img_format" != "qcow2" ]]; then
            local temp_file="$IMG_FILE.tmp"
            if qemu-img convert -f "$img_format" -O qcow2 "$IMG_FILE" "$temp_file" 2>/dev/null; then
                mv "$temp_file" "$IMG_FILE"
            fi
        fi

        # Resize
        qemu-img resize "$IMG_FILE" "$DISK_SIZE" 2>/dev/null || true
    fi

    print_status "SUCCESS" "Disk image created: $IMG_FILE"

    # Create cloud-init configuration
    print_status "INFO" "Creating cloud-init configuration..."

    # Generate password hash - IMPROVED
    local password_hash
    password_hash=$(generate_password_hash "$PASSWORD")

    local use_hashed_password=true
    if [[ -z "$password_hash" ]]; then
        print_status "WARN" "Could not generate password hash, using plain password method"
        use_hashed_password=false
    else
        print_status "SUCCESS" "Password hash generated successfully"
    fi

    # IMPROVED: Better cloud-init configuration with multiple fallback methods
    if $use_hashed_password; then
        cat > user-data <<EOF
#cloud-config
hostname: $HOSTNAME
fqdn: $HOSTNAME.local
manage_etc_hosts: true
preserve_hostname: false

# User configuration with hashed password
users:
  - name: $USERNAME
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: [sudo, adm, wheel, systemd-journal]
    shell: /bin/bash
    lock_passwd: false
    hashed_passwd: $password_hash
    ssh_pwauth: true

# Also set root password
chpasswd:
  expire: false
  list:
    - root:$PASSWORD
    - $USERNAME:$PASSWORD

# Enable SSH password authentication
ssh_pwauth: true
disable_root: false

# SSH configuration - ensure password auth works
write_files:
  - path: /etc/ssh/sshd_config.d/99-cloud-init-pwauth.conf
    content: |
      PasswordAuthentication yes
      PermitRootLogin yes
      ChallengeResponseAuthentication no
      UsePAM yes
    permissions: '0644'
  - path: /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
    content: |
      network: {config: disabled}
    permissions: '0644'

# Run commands to ensure everything works
runcmd:
  # Set passwords directly as backup
  - echo "$USERNAME:$PASSWORD" | chpasswd
  - echo "root:$PASSWORD" | chpasswd
  # Unlock accounts
  - passwd -u $USERNAME || true
  - passwd -u root || true
  # Ensure user exists with proper shell
  - usermod -s /bin/bash $USERNAME || true
  # Restart SSH
  - systemctl restart sshd || systemctl restart ssh || service sshd restart || service ssh restart || true
  # Log completion
  - echo "Cloud-init setup completed at \$(date)" >> /var/log/cloud-init-custom.log
  - echo "User: $USERNAME Password: $PASSWORD" >> /var/log/cloud-init-custom.log

final_message: |
  ========================================
  Cloud-init setup complete!
  VM: $VM_NAME
  Hostname: $HOSTNAME
  User: $USERNAME
  Password: $PASSWORD
  SSH: ssh -p $SSH_PORT $USERNAME@localhost
  ========================================
EOF
    else
        # Fallback: Use plain password (some cloud-init versions handle this)
        cat > user-data <<EOF
#cloud-config
hostname: $HOSTNAME
fqdn: $HOSTNAME.local
manage_etc_hosts: true
preserve_hostname: false

# User configuration with plain password
users:
  - name: $USERNAME
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: [sudo, adm, wheel, systemd-journal]
    shell: /bin/bash
    lock_passwd: false
    plain_text_passwd: $PASSWORD
    ssh_pwauth: true

# Set passwords
chpasswd:
  expire: false
  list:
    - root:$PASSWORD
    - $USERNAME:$PASSWORD

# Enable SSH password authentication
ssh_pwauth: true
disable_root: false

# SSH configuration
write_files:
  - path: /etc/ssh/sshd_config.d/99-cloud-init-pwauth.conf
    content: |
      PasswordAuthentication yes
      PermitRootLogin yes
      ChallengeResponseAuthentication no
      UsePAM yes
    permissions: '0644'

# Run commands
runcmd:
  # Set passwords directly
  - echo "$USERNAME:$PASSWORD" | chpasswd
  - echo "root:$PASSWORD" | chpasswd
  # Unlock accounts
  - passwd -u $USERNAME || true
  - passwd -u root || true
  # Ensure user has proper shell
  - usermod -s /bin/bash $USERNAME || true
  # Restart SSH
  - systemctl restart sshd || systemctl restart ssh || service sshd restart || service ssh restart || true
  - echo "Cloud-init setup completed at \$(date)" >> /var/log/cloud-init-custom.log

final_message: |
  Cloud-init complete! User: $USERNAME
EOF
    fi

    # Create meta-data
    cat > meta-data <<EOF
instance-id: iid-$VM_NAME-$(date +%s)
local-hostname: $HOSTNAME
EOF

    # Create seed ISO
    if ! create_cloud_init_iso "user-data" "meta-data" "$SEED_FILE"; then
        print_status "ERROR" "Failed to create cloud-init seed image"
        cleanup
        return 1
    fi

    # Cleanup temporary files
    cleanup

    print_status "SUCCESS" "Cloud-init configuration created"
    return 0
}

# IMPROVED: QEMU command builder with better compatibility
build_qemu_command_foreground() {
    local vm_name=$1

    QEMU_CMD=()
    QEMU_CMD+=(qemu-system-x86_64)

    # Machine type
    QEMU_CMD+=(-machine type=q35,accel=kvm:tcg)

    # Add KVM if available
    if $KVM_AVAILABLE; then
        QEMU_CMD+=(-enable-kvm)
        QEMU_CMD+=(-cpu host)
    else
        QEMU_CMD+=(-cpu qemu64)
    fi

    # Basic configuration
    QEMU_CMD+=(-name "$vm_name")
    QEMU_CMD+=(-m "$MEMORY")
    QEMU_CMD+=(-smp "$CPUS")

    # Disk drives - FIXED: compatible options
    QEMU_CMD+=(-drive "file=$IMG_FILE,format=qcow2,if=virtio,cache=writeback,discard=unmap")

    # Add seed drive if exists
    if [[ -f "$SEED_FILE" ]]; then
        QEMU_CMD+=(-drive "file=$SEED_FILE,format=raw,if=virtio,readonly=on")
    fi

    QEMU_CMD+=(-boot order=c)

    # Build network configuration with all port forwards
    local netdev_opts="user,id=net0,hostfwd=tcp::${SSH_PORT}-:22"

    if [[ -n "${PORT_FORWARDS:-}" ]]; then
        IFS=',' read -ra forwards <<< "$PORT_FORWARDS"
        for forward in "${forwards[@]}"; do
            forward=$(echo "$forward" | tr -d ' ')
            if [[ "$forward" =~ ^[0-9]+:[0-9]+$ ]]; then
                IFS=':' read -r host_port guest_port <<< "$forward"
                netdev_opts+=",hostfwd=tcp::${host_port}-:${guest_port}"
            fi
        done
    fi

    QEMU_CMD+=(-device virtio-net-pci,netdev=net0)
    QEMU_CMD+=(-netdev "$netdev_opts")

    # Display configuration - foreground mode
    if [[ "$GUI_MODE" == "true" ]]; then
        QEMU_CMD+=(-vga virtio)
        QEMU_CMD+=(-display gtk)
    else
        QEMU_CMD+=(-nographic)
        QEMU_CMD+=(-serial mon:stdio)
    fi

    # Performance enhancements
    QEMU_CMD+=(-device virtio-balloon-pci,id=balloon0)
    QEMU_CMD+=(-object rng-random,filename=/dev/urandom,id=rng0)
    QEMU_CMD+=(-device virtio-rng-pci,rng=rng0)
}

# Function to build QEMU command for background
build_qemu_command_background() {
    local vm_name=$1

    QEMU_CMD=()
    QEMU_CMD+=(qemu-system-x86_64)

    # Machine type with fallback
    QEMU_CMD+=(-machine type=q35,accel=kvm:tcg)

    # Add KVM if available
    if $KVM_AVAILABLE; then
        QEMU_CMD+=(-enable-kvm)
        QEMU_CMD+=(-cpu host)
    else
        QEMU_CMD+=(-cpu qemu64)
    fi

    # Basic configuration
    QEMU_CMD+=(-name "$vm_name")
    QEMU_CMD+=(-m "$MEMORY")
    QEMU_CMD+=(-smp "$CPUS")

    # Disk drives - compatible options
    QEMU_CMD+=(-drive "file=$IMG_FILE,format=qcow2,if=virtio,cache=writeback,discard=unmap")

    # Add seed drive if exists
    if [[ -f "$SEED_FILE" ]]; then
        QEMU_CMD+=(-drive "file=$SEED_FILE,format=raw,if=virtio,readonly=on")
    fi

    QEMU_CMD+=(-boot order=c)

    # Build network configuration
    local netdev_opts="user,id=net0,hostfwd=tcp::${SSH_PORT}-:22"

    if [[ -n "${PORT_FORWARDS:-}" ]]; then
        IFS=',' read -ra forwards <<< "$PORT_FORWARDS"
        for forward in "${forwards[@]}"; do
            forward=$(echo "$forward" | tr -d ' ')
            if [[ "$forward" =~ ^[0-9]+:[0-9]+$ ]]; then
                IFS=':' read -r host_port guest_port <<< "$forward"
                netdev_opts+=",hostfwd=tcp::${host_port}-:${guest_port}"
            fi
        done
    fi

    QEMU_CMD+=(-device virtio-net-pci,netdev=net0)
    QEMU_CMD+=(-netdev "$netdev_opts")

    # Background mode - no display, daemonize
    QEMU_CMD+=(-display none)
    QEMU_CMD+=(-daemonize)

    # Enable monitor via unix socket for management
    QEMU_CMD+=(-monitor "unix:$VM_DIR/$vm_name.monitor,server,nowait")

    # Performance enhancements
    QEMU_CMD+=(-device virtio-balloon-pci,id=balloon0)
    QEMU_CMD+=(-object rng-random,filename=/dev/urandom,id=rng0)
    QEMU_CMD+=(-device virtio-rng-pci,rng=rng0)
}

# Function to start a VM in foreground
start_vm() {
    local vm_name=$1

    if ! load_vm_config "$vm_name"; then
        return 1
    fi

    # Check if already running
    if is_vm_running "$vm_name"; then
        print_status "WARN" "VM '$vm_name' is already running"
        return 1
    fi

    # Check if image file exists
    if [[ ! -f "$IMG_FILE" ]]; then
        print_status "ERROR" "VM image file not found: $IMG_FILE"
        return 1
    fi

    # Check if seed file exists
    if [[ ! -f "$SEED_FILE" ]]; then
        print_status "WARN" "Seed file not found, recreating..."
        setup_vm_image
    fi

    # Check if port is available
    if ! is_port_available "$SSH_PORT"; then
        print_status "ERROR" "SSH port $SSH_PORT is already in use"
        local new_port
        new_port=$(find_available_port "$SSH_PORT")
        read -p "$(print_status "INPUT" "Use port $new_port instead? (Y/n): ")" use_new
        if [[ ! "$use_new" =~ ^[Nn]$ ]]; then
            SSH_PORT="$new_port"
            save_vm_config
        else
            return 1
        fi
    fi

    echo
    print_status "INFO" "Starting VM: $vm_name"
    echo "════════════════════════════════════════════"
    echo "  OS       : $OS_TYPE $OS_VERSION"
    echo "  SSH      : ssh -p $SSH_PORT $USERNAME@localhost"
    echo "  Username : $USERNAME"
    echo "  Password : $PASSWORD"
    if [[ -n "${PORT_FORWARDS:-}" ]]; then
        echo "  Ports    : $PORT_FORWARDS"
    fi
    echo "════════════════════════════════════════════"
    echo

    if [[ "$GUI_MODE" != "true" ]]; then
        print_status "INFO" "Console mode - Press Ctrl+A, X to exit QEMU"
    fi

    # Build QEMU command
    build_qemu_command_foreground "$vm_name"

    print_status "INFO" "Launching QEMU..."
    echo

    # Run QEMU
    "${QEMU_CMD[@]}"
    local exit_code=$?

    echo
    if [ $exit_code -eq 0 ]; then
        print_status "INFO" "VM '$vm_name' has been shut down"
    else
        print_status "ERROR" "QEMU exited with error code: $exit_code"
        return 1
    fi
}

# Function to start VM in background
start_vm_background() {
    local vm_name=$1

    if ! load_vm_config "$vm_name"; then
        return 1
    fi

    if is_vm_running "$vm_name"; then
        print_status "WARN" "VM '$vm_name' is already running"
        return 1
    fi

    if [[ ! -f "$IMG_FILE" ]]; then
        print_status "ERROR" "VM image file not found: $IMG_FILE"
        return 1
    fi

    if [[ ! -f "$SEED_FILE" ]]; then
        print_status "WARN" "Seed file not found, recreating..."
        setup_vm_image
    fi

    if ! is_port_available "$SSH_PORT"; then
        print_status "ERROR" "SSH port $SSH_PORT is already in use"
        local new_port
        new_port=$(find_available_port "$SSH_PORT")
        read -p "$(print_status "INPUT" "Use port $new_port instead? (Y/n): ")" use_new
        if [[ ! "$use_new" =~ ^[Nn]$ ]]; then
            SSH_PORT="$new_port"
            save_vm_config
        else
            return 1
        fi
    fi

    print_status "INFO" "Starting VM '$vm_name' in background..."

    # Build background QEMU command
    build_qemu_command_background "$vm_name"

    # Run QEMU in background
    if "${QEMU_CMD[@]}" 2>/dev/null; then
        sleep 2

        if is_vm_running "$vm_name"; then
            echo
            print_status "SUCCESS" "VM '$vm_name' started in background"
            echo "════════════════════════════════════════════"
            echo "  SSH      : ssh -p $SSH_PORT $USERNAME@localhost"
            echo "  Username : $USERNAME"
            echo "  Password : $PASSWORD"
            echo "════════════════════════════════════════════"
            print_status "INFO" "Wait ~30-60 seconds for cloud-init to complete before SSH"
        else
            print_status "ERROR" "VM may have failed to start"
            print_status "INFO" "Try starting in foreground mode to see errors"
            return 1
        fi
    else
        print_status "ERROR" "Failed to start VM"
        print_status "INFO" "Try starting in foreground mode to see errors"
        return 1
    fi
}

# Function to check if VM is running
is_vm_running() {
    local vm_name=$1
    pgrep -f "qemu-system-x86_64.*-name ${vm_name}( |$)" >/dev/null 2>&1
}

# Function to get VM PID
get_vm_pid() {
    local vm_name=$1
    pgrep -f "qemu-system-x86_64.*-name ${vm_name}( |$)" 2>/dev/null | head -1
}

# Function to stop a running VM
stop_vm() {
    local vm_name=$1

    if ! load_vm_config "$vm_name"; then
        return 1
    fi

    if ! is_vm_running "$vm_name"; then
        print_status "INFO" "VM '$vm_name' is not running"
        return 0
    fi

    print_status "INFO" "Stopping VM: $vm_name"

    local pid
    pid=$(get_vm_pid "$vm_name")

    if [[ -n "$pid" ]]; then
        # Try graceful shutdown via monitor socket first
        if [[ -S "$VM_DIR/$vm_name.monitor" ]]; then
            echo "system_powerdown" | socat - "UNIX-CONNECT:$VM_DIR/$vm_name.monitor" 2>/dev/null || true
            sleep 2
        fi

        # Try SIGTERM
        kill -TERM "$pid" 2>/dev/null || true

        echo -n "Waiting for VM to stop"
        local count=0
        while is_vm_running "$vm_name" && [ $count -lt 15 ]; do
            sleep 1
            ((count++))
            echo -n "."
        done
        echo

        # Force kill if still running
        if is_vm_running "$vm_name"; then
            print_status "WARN" "VM did not stop gracefully, forcing termination..."
            kill -9 "$pid" 2>/dev/null || true
            sleep 1
        fi
    fi

    # Cleanup monitor socket if exists
    [[ -S "$VM_DIR/$vm_name.monitor" ]] && rm -f "$VM_DIR/$vm_name.monitor"

    if ! is_vm_running "$vm_name"; then
        print_status "SUCCESS" "VM '$vm_name' stopped"
    else
        print_status "ERROR" "Failed to stop VM '$vm_name'"
        return 1
    fi
}

# Function to delete a VM
delete_vm() {
    local vm_name=$1

    if ! load_vm_config "$vm_name"; then
        return 1
    fi

    if is_vm_running "$vm_name"; then
        print_status "ERROR" "VM '$vm_name' is running. Stop it first."
        return 1
    fi

    echo
    print_status "WARN" "This will permanently delete VM '$vm_name' and all its data!"
    print_status "WARN" "Files to be deleted:"
    [[ -f "$IMG_FILE" ]] && echo "  - $IMG_FILE"
    [[ -f "$SEED_FILE" ]] && echo "  - $SEED_FILE"
    echo "  - $VM_DIR/$vm_name.conf"
    echo

    read -p "$(print_status "INPUT" "Type 'DELETE' to confirm: ")" confirm

    if [[ "$confirm" == "DELETE" ]]; then
        rm -f "$IMG_FILE" "$SEED_FILE" "$VM_DIR/$vm_name.conf" "$VM_DIR/$vm_name.monitor"
        print_status "SUCCESS" "VM '$vm_name' has been deleted"
    else
        print_status "INFO" "Deletion cancelled"
    fi
}

# Function to show VM info
show_vm_info() {
    local vm_name=$1

    if ! load_vm_config "$vm_name"; then
        return 1
    fi

    local status="Stopped"
    local status_color="\033[1;31m"
    if is_vm_running "$vm_name"; then
        status="Running"
        status_color="\033[1;32m"
    fi

    echo
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                        VM Information                            ║"
    echo "╠══════════════════════════════════════════════════════════════════╣"
    printf "║  %-15s : %-48s ║\n" "Name" "$VM_NAME"
    printf "║  %-15s : ${status_color}%-48s\033[0m ║\n" "Status" "$status"
    printf "║  %-15s : %-48s ║\n" "OS" "$OS_TYPE $OS_VERSION"
    printf "║  %-15s : %-48s ║\n" "Codename" "$CODENAME"
    printf "║  %-15s : %-48s ║\n" "Hostname" "$HOSTNAME"
    printf "║  %-15s : %-48s ║\n" "Username" "$USERNAME"
    printf "║  %-15s : %-48s ║\n" "Password" "$PASSWORD"
    echo "╠══════════════════════════════════════════════════════════════════╣"
    printf "║  %-15s : %-48s ║\n" "SSH Port" "$SSH_PORT"
    printf "║  %-15s : %-48s ║\n" "Memory" "${MEMORY} MB"
    printf "║  %-15s : %-48s ║\n" "CPUs" "$CPUS"
    printf "║  %-15s : %-48s ║\n" "Disk Size" "$DISK_SIZE"
    printf "║  %-15s : %-48s ║\n" "GUI Mode" "$GUI_MODE"
    printf "║  %-15s : %-48s ║\n" "Port Forwards" "${PORT_FORWARDS:-None}"
    echo "╠══════════════════════════════════════════════════════════════════╣"
    printf "║  %-15s : %-48s ║\n" "Created" "$CREATED"
    echo "╚══════════════════════════════════════════════════════════════════╝"

    if [[ -f "$IMG_FILE" ]]; then
        echo
        echo "Disk Information:"
        qemu-img info "$IMG_FILE" 2>/dev/null | grep -E "virtual size|disk size|backing file" | sed 's/^/  /'
    fi

    echo
    print_status "INFO" "SSH command:"
    echo "  ssh -p $SSH_PORT $USERNAME@localhost"
    echo

    read -p "$(print_status "INPUT" "Press Enter to continue...")"
}

# Function to edit VM configuration
edit_vm_config() {
    local vm_name=$1

    if ! load_vm_config "$vm_name"; then
        return 1
    fi

    local was_running=false
    if is_vm_running "$vm_name"; then
        was_running=true
        print_status "WARN" "VM is running. Some changes require restart."
    fi

    while true; do
        echo
        print_status "INFO" "Editing VM: $vm_name"
        echo "╔═════════════════════════════════════════════╗"
        echo "║          Configuration Options              ║"
        echo "╠═════════════════════════════════════════════╣"
        printf "║  1) Hostname       : %-22s ║\n" "$HOSTNAME"
        printf "║  2) Username       : %-22s ║\n" "$USERNAME"
        printf "║  3) Password       : %-22s ║\n" "****"
        printf "║  4) SSH Port       : %-22s ║\n" "$SSH_PORT"
        printf "║  5) Memory (MB)    : %-22s ║\n" "$MEMORY"
        printf "║  6) CPU Count      : %-22s ║\n" "$CPUS"
        printf "║  7) GUI Mode       : %-22s ║\n" "$GUI_MODE"
        printf "║  8) Port Forwards  : %-22s ║\n" "${PORT_FORWARDS:-None}"
        echo "╠═════════════════════════════════════════════╣"
        echo "║  0) Save and exit                           ║"
        echo "╚═════════════════════════════════════════════╝"

        read -p "$(print_status "INPUT" "Enter your choice: ")" edit_choice

        local need_rebuild=false

        case $edit_choice in
            1)
                while true; do
                    read -p "$(print_status "INPUT" "New hostname [$HOSTNAME]: ")" new_val
                    new_val="${new_val:-$HOSTNAME}"
                    if validate_input "name" "$new_val"; then
                        HOSTNAME="$new_val"
                        need_rebuild=true
                        break
                    fi
                done
                ;;
            2)
                while true; do
                    read -p "$(print_status "INPUT" "New username [$USERNAME]: ")" new_val
                    new_val="${new_val:-$USERNAME}"
                    if validate_input "username" "$new_val"; then
                        USERNAME="$new_val"
                        need_rebuild=true
                        break
                    fi
                done
                ;;
            3)
                while true; do
                    read -s -p "$(print_status "INPUT" "New password: ")" new_val
                    echo
                    new_val="${new_val:-$PASSWORD}"
                    if validate_input "password" "$new_val"; then
                        PASSWORD="$new_val"
                        need_rebuild=true
                        break
                    fi
                done
                ;;
            4)
                while true; do
                    read -p "$(print_status "INPUT" "New SSH port [$SSH_PORT]: ")" new_val
                    new_val="${new_val:-$SSH_PORT}"
                    if validate_input "port" "$new_val"; then
                        if [ "$new_val" != "$SSH_PORT" ] && ! is_port_available "$new_val"; then
                            print_status "ERROR" "Port $new_val is in use"
                        else
                            SSH_PORT="$new_val"
                            break
                        fi
                    fi
                done
                ;;
            5)
                while true; do
                    read -p "$(print_status "INPUT" "New memory in MB [$MEMORY]: ")" new_val
                    new_val="${new_val:-$MEMORY}"
                    if validate_input "number" "$new_val"; then
                        MEMORY="$new_val"
                        break
                    fi
                done
                ;;
            6)
                while true; do
                    read -p "$(print_status "INPUT" "New CPU count [$CPUS]: ")" new_val
                    new_val="${new_val:-$CPUS}"
                    if validate_input "number" "$new_val"; then
                        CPUS="$new_val"
                        break
                    fi
                done
                ;;
            7)
                if [[ "$GUI_MODE" == "true" ]]; then
                    GUI_MODE="false"
                else
                    GUI_MODE="true"
                fi
                print_status "SUCCESS" "GUI mode set to: $GUI_MODE"
                ;;
            8)
                read -p "$(print_status "INPUT" "Port forwards (e.g., 8080:80,3000:3000): ")" PORT_FORWARDS
                ;;
            0)
                # Rebuild cloud-init if needed
                if $need_rebuild; then
                    print_status "INFO" "Rebuilding cloud-init configuration..."
                    setup_vm_image
                    if $was_running; then
                        print_status "WARN" "Restart the VM for changes to take effect"
                    fi
                fi
                save_vm_config
                return 0
                ;;
            *)
                print_status "ERROR" "Invalid selection"
                ;;
        esac
    done
}

# Function to clone a VM
clone_vm() {
    local source_vm=$1

    if ! load_vm_config "$source_vm"; then
        return 1
    fi

    if is_vm_running "$source_vm"; then
        print_status "WARN" "Cloning a running VM may result in inconsistent data"
        read -p "$(print_status "INPUT" "Continue anyway? (y/N): ")" confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            return 1
        fi
    fi

    local source_name="$VM_NAME"
    local source_img="$IMG_FILE"

    while true; do
        read -p "$(print_status "INPUT" "Enter name for cloned VM: ")" new_name
        if [[ -z "$new_name" ]]; then
            print_status "ERROR" "Name cannot be empty"
            continue
        fi
        if validate_input "name" "$new_name"; then
            if [[ -f "$VM_DIR/$new_name.conf" ]]; then
                print_status "ERROR" "VM '$new_name' already exists"
            else
                break
            fi
        fi
    done

    print_status "INFO" "Cloning VM '$source_name' to '$new_name'..."

    # Update VM name and file paths
    VM_NAME="$new_name"
    HOSTNAME="$new_name"
    IMG_FILE="$VM_DIR/$new_name.qcow2"
    SEED_FILE="$VM_DIR/$new_name-seed.iso"
    CREATED="$(date '+%Y-%m-%d %H:%M:%S') (cloned from $source_name)"

    # Find new SSH port
    SSH_PORT=$(find_available_port "$SSH_PORT")

    # Clone the disk
    print_status "INFO" "Copying disk image (this may take a while)..."
    if ! cp "$source_img" "$IMG_FILE"; then
        print_status "ERROR" "Failed to copy disk image"
        return 1
    fi

    # Create new cloud-init
    setup_vm_image

    # Save new configuration
    save_vm_config

    print_status "SUCCESS" "VM '$new_name' cloned successfully"
    print_status "INFO" "New SSH port: $SSH_PORT"
}

# Function to create snapshot
create_snapshot() {
    local vm_name=$1

    if ! load_vm_config "$vm_name"; then
        return 1
    fi

    read -p "$(print_status "INPUT" "Enter snapshot name: ")" snapshot_name

    if [[ -z "$snapshot_name" ]]; then
        print_status "ERROR" "Snapshot name cannot be empty"
        return 1
    fi

    if ! validate_input "name" "$snapshot_name"; then
        return 1
    fi

    print_status "INFO" "Creating snapshot '$snapshot_name'..."

    if qemu-img snapshot -c "$snapshot_name" "$IMG_FILE" 2>/dev/null; then
        print_status "SUCCESS" "Snapshot '$snapshot_name' created"
    else
        print_status "ERROR" "Failed to create snapshot"
        return 1
    fi
}

# Function to list snapshots
list_snapshots() {
    local vm_name=$1

    if ! load_vm_config "$vm_name"; then
        return 1
    fi

    echo
    print_status "INFO" "Snapshots for VM '$vm_name':"
    echo

    local output
    output=$(qemu-img snapshot -l "$IMG_FILE" 2>/dev/null)

    if [[ -n "$output" ]] && [[ "$output" != *"no snapshots"* ]]; then
        echo "$output"
    else
        echo "  No snapshots found"
    fi

    echo
    read -p "$(print_status "INPUT" "Press Enter to continue...")"
}

# Function to restore snapshot
restore_snapshot() {
    local vm_name=$1

    if ! load_vm_config "$vm_name"; then
        return 1
    fi

    if is_vm_running "$vm_name"; then
        print_status "ERROR" "Stop the VM before restoring a snapshot"
        return 1
    fi

    echo
    print_status "INFO" "Available snapshots:"
    qemu-img snapshot -l "$IMG_FILE" 2>/dev/null || {
        print_status "ERROR" "No snapshots found"
        return 1
    }

    echo
    read -p "$(print_status "INPUT" "Enter snapshot name to restore: ")" snapshot_name

    if [[ -z "$snapshot_name" ]]; then
        print_status "ERROR" "Snapshot name cannot be empty"
        return 1
    fi

    print_status "WARN" "This will restore VM to snapshot '$snapshot_name'"
    read -p "$(print_status "INPUT" "Are you sure? (y/N): ")" confirm

    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        if qemu-img snapshot -a "$snapshot_name" "$IMG_FILE" 2>/dev/null; then
            print_status "SUCCESS" "Snapshot '$snapshot_name' restored"
        else
            print_status "ERROR" "Failed to restore snapshot"
            return 1
        fi
    else
        print_status "INFO" "Restore cancelled"
    fi
}

# Function to delete snapshot
delete_snapshot() {
    local vm_name=$1

    if ! load_vm_config "$vm_name"; then
        return 1
    fi

    echo
    print_status "INFO" "Available snapshots:"
    qemu-img snapshot -l "$IMG_FILE" 2>/dev/null || {
        print_status "ERROR" "No snapshots found"
        return 1
    }

    echo
    read -p "$(print_status "INPUT" "Enter snapshot name to delete: ")" snapshot_name

    if [[ -z "$snapshot_name" ]]; then
        print_status "ERROR" "Snapshot name cannot be empty"
        return 1
    fi

    read -p "$(print_status "INPUT" "Delete snapshot '$snapshot_name'? (y/N): ")" confirm

    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        if qemu-img snapshot -d "$snapshot_name" "$IMG_FILE" 2>/dev/null; then
            print_status "SUCCESS" "Snapshot '$snapshot_name' deleted"
        else
            print_status "ERROR" "Failed to delete snapshot"
            return 1
        fi
    fi
}

# Function to resize VM disk
resize_vm_disk() {
    local vm_name=$1

    if ! load_vm_config "$vm_name"; then
        return 1
    fi

    if is_vm_running "$vm_name"; then
        print_status "ERROR" "Stop the VM before resizing disk"
        return 1
    fi

    echo
    print_status "INFO" "Current disk configuration:"
    echo "  Configured size: $DISK_SIZE"
    qemu-img info "$IMG_FILE" 2>/dev/null | grep -E "virtual size|disk size" | sed 's/^/  /'
    echo

    while true; do
        read -p "$(print_status "INPUT" "Enter new disk size (e.g., 50G): ")" new_size
        if [[ -z "$new_size" ]]; then
            print_status "INFO" "Resize cancelled"
            return 0
        fi
        if validate_input "size" "$new_size"; then
            break
        fi
    done

    print_status "WARN" "Disk can only be expanded, not shrunk"
    read -p "$(print_status "INPUT" "Resize disk to $new_size? (y/N): ")" confirm

    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        if qemu-img resize "$IMG_FILE" "$new_size" 2>/dev/null; then
            DISK_SIZE="$new_size"
            save_vm_config
            print_status "SUCCESS" "Disk resized to $new_size"
            print_status "INFO" "You may need to extend the filesystem inside the VM"
        else
            print_status "ERROR" "Failed to resize disk"
            return 1
        fi
    else
        print_status "INFO" "Resize cancelled"
    fi
}

# Function to show system info
show_system_info() {
    echo
    print_status "INFO" "System Information"
    echo "════════════════════════════════════════════"
    echo "  Hostname      : $(hostname 2>/dev/null || echo 'unknown')"
    echo "  Kernel        : $(uname -r 2>/dev/null || echo 'unknown')"
    echo "  Architecture  : $(uname -m 2>/dev/null || echo 'unknown')"
    echo "  Host CPUs     : $(nproc 2>/dev/null || echo 'unknown')"
    echo "  Total Memory  : $(free -h 2>/dev/null | awk '/^Mem:/ {print $2}' || echo 'unknown')"
    echo "  Free Memory   : $(free -h 2>/dev/null | awk '/^Mem:/ {print $4}' || echo 'unknown')"

    if [[ -d "$VM_DIR" ]]; then
        echo "  VM Directory  : $VM_DIR"
        echo "  VM Disk Free  : $(df -h "$VM_DIR" 2>/dev/null | awk 'NR==2 {print $4}' || echo 'unknown')"
    fi

    echo "  KVM Available : $KVM_AVAILABLE"
    echo "  QEMU Version  : $(qemu-system-x86_64 --version 2>/dev/null | head -1 | awk '{print $4}' || echo 'unknown')"
    echo "════════════════════════════════════════════"
    echo
    read -p "$(print_status "INPUT" "Press Enter to continue...")"
}

# Snapshot submenu
snapshot_menu() {
    local vm_name=$1

    while true; do
        echo
        print_status "INFO" "Snapshot Management: $vm_name"
        echo "╔═══════════════════════════════════════╗"
        echo "║  1) Create snapshot                   ║"
        echo "║  2) List snapshots                    ║"
        echo "║  3) Restore snapshot                  ║"
        echo "║  4) Delete snapshot                   ║"
        echo "║  0) Back                              ║"
        echo "╚═══════════════════════════════════════╝"

        read -p "$(print_status "INPUT" "Enter your choice: ")" choice

        case $choice in
            1) create_snapshot "$vm_name" ;;
            2) list_snapshots "$vm_name" ;;
            3) restore_snapshot "$vm_name" ;;
            4) delete_snapshot "$vm_name" ;;
            0) return 0 ;;
            *) print_status "ERROR" "Invalid option" ;;
        esac
    done
}

# Function to select VM
select_vm() {
    local prompt=$1
    shift
    local vms=("$@")
    local vm_count=${#vms[@]}

    if [ "$vm_count" -eq 0 ]; then
        print_status "ERROR" "No VMs found"
        return 1
    fi

    read -p "$(print_status "INPUT" "$prompt (1-$vm_count): ")" vm_num

    if [[ "$vm_num" =~ ^[0-9]+$ ]] && [ "$vm_num" -ge 1 ] && [ "$vm_num" -le "$vm_count" ]; then
        echo "${vms[$((vm_num-1))]}"
        return 0
    else
        print_status "ERROR" "Invalid selection"
        return 1
    fi
}

# Main menu function
main_menu() {
    while true; do
        display_header

        # Get VM list
        local vms=()
        while IFS= read -r vm; do
            [[ -n "$vm" ]] && vms+=("$vm")
        done < <(get_vm_list)

        local vm_count=${#vms[@]}

        if [ "$vm_count" -gt 0 ]; then
            print_status "INFO" "Virtual Machines ($vm_count):"
            echo
            for i in "${!vms[@]}"; do
                local status="○ Stopped"
                local status_color="\033[1;31m"
                if is_vm_running "${vms[$i]}"; then
                    status="● Running"
                    status_color="\033[1;32m"
                fi
                printf "  %2d) %-30s ${status_color}%s\033[0m\n" "$((i+1))" "${vms[$i]}" "$status"
            done
            echo
        else
            print_status "INFO" "No VMs found. Create one to get started!"
            echo
        fi

        echo "╔═════════════════════════════════════════╗"
        echo "║              Main Menu                  ║"
        echo "╠═════════════════════════════════════════╣"
        echo "║   1) Create new VM                      ║"
        if [ "$vm_count" -gt 0 ]; then
        echo "║   2) Start VM (foreground)              ║"
        echo "║   3) Start VM (background)              ║"
        echo "║   4) Stop VM                            ║"
        echo "║   5) Show VM info                       ║"
        echo "║   6) Edit VM configuration              ║"
        echo "║   7) Clone VM                           ║"
        echo "║   8) Snapshot management                ║"
        echo "║   9) Resize VM disk                     ║"
        echo "║  10) Delete VM                          ║"
        fi
        echo "╠═════════════════════════════════════════╣"
        echo "║   s) System information                 ║"
        echo "║   0) Exit                               ║"
        echo "╚═════════════════════════════════════════╝"
        echo

        read -p "$(print_status "INPUT" "Enter your choice: ")" choice

        case $choice in
            1)
                create_new_vm
                ;;
            2)
                if [ "$vm_count" -gt 0 ]; then
                    vm_name=$(select_vm "Select VM to start" "${vms[@]}") && start_vm "$vm_name"
                fi
                ;;
            3)
                if [ "$vm_count" -gt 0 ]; then
                    vm_name=$(select_vm "Select VM to start in background" "${vms[@]}") && start_vm_background "$vm_name"
                fi
                ;;
            4)
                if [ "$vm_count" -gt 0 ]; then
                    vm_name=$(select_vm "Select VM to stop" "${vms[@]}") && stop_vm "$vm_name"
                fi
                ;;
            5)
                if [ "$vm_count" -gt 0 ]; then
                    vm_name=$(select_vm "Select VM to show info" "${vms[@]}") && show_vm_info "$vm_name"
                fi
                ;;
            6)
                if [ "$vm_count" -gt 0 ]; then
                    vm_name=$(select_vm "Select VM to edit" "${vms[@]}") && edit_vm_config "$vm_name"
                fi
                ;;
            7)
                if [ "$vm_count" -gt 0 ]; then
                    vm_name=$(select_vm "Select VM to clone" "${vms[@]}") && clone_vm "$vm_name"
                fi
                ;;
            8)
                if [ "$vm_count" -gt 0 ]; then
                    vm_name=$(select_vm "Select VM for snapshots" "${vms[@]}") && snapshot_menu "$vm_name"
                fi
                ;;
            9)
                if [ "$vm_count" -gt 0 ]; then
                    vm_name=$(select_vm "Select VM to resize" "${vms[@]}") && resize_vm_disk "$vm_name"
                fi
                ;;
            10)
                if [ "$vm_count" -gt 0 ]; then
                    vm_name=$(select_vm "Select VM to delete" "${vms[@]}") && delete_vm "$vm_name"
                fi
                ;;
            s|S)
                show_system_info
                ;;
            0|q|Q)
                echo
                print_status "INFO" "Goodbye! May Allah bless you."
                echo
                exit 0
                ;;
            *)
                print_status "ERROR" "Invalid option"
                sleep 1
                ;;
        esac

        echo
        read -p "$(print_status "INPUT" "Press Enter to continue...")"
    done
}

# ============================================
# Initialization
# ============================================

# Set trap to cleanup on exit
trap cleanup EXIT

# Initialize paths
VM_DIR="${VM_DIR:-$HOME/vms}"
mkdir -p "$VM_DIR"

# Display header
display_header

# Check dependencies
print_status "INFO" "Checking system requirements..."
check_dependencies
check_kvm
echo

# ============================================
# Supported OS List - LATEST VERSIONS (2024-2025)
# Format: OS_TYPE|OS_VERSION|CODENAME|IMG_URL|DEFAULT_HOSTNAME|DEFAULT_USERNAME|DEFAULT_PASSWORD
# ============================================

declare -A OS_OPTIONS=(
    # Ubuntu - LTS and Latest Releases
    ["Ubuntu 22.04 LTS (Jammy)"]="ubuntu|22.04|jammy|https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img|ubuntu22|ubuntu|ubuntu"
    ["Ubuntu 24.04 LTS (Noble)"]="ubuntu|24.04|noble|https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img|ubuntu24|ubuntu|ubuntu"
    ["Ubuntu 24.10 (Oracular)"]="ubuntu|24.10|oracular|https://cloud-images.ubuntu.com/oracular/current/oracular-server-cloudimg-amd64.img|ubuntu2410|ubuntu|ubuntu"
    ["Ubuntu 25.04 (Plucky) [Dev]"]="ubuntu|25.04|plucky|https://cloud-images.ubuntu.com/plucky/current/plucky-server-cloudimg-amd64.img|ubuntu25|ubuntu|ubuntu"

    # Debian - Stable and Testing
    ["Debian 11 (Bullseye)"]="debian|11|bullseye|https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-generic-amd64.qcow2|debian11|debian|debian"
    ["Debian 12 (Bookworm)"]="debian|12|bookworm|https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2|debian12|debian|debian"
    ["Debian 13 (Trixie) [Testing]"]="debian|13|trixie|https://cloud.debian.org/images/cloud/trixie/daily/latest/debian-13-generic-amd64-daily.qcow2|debian13|debian|debian"

    # Fedora - Latest
    ["Fedora 40"]="fedora|40|40|https://download.fedoraproject.org/pub/fedora/linux/releases/40/Cloud/x86_64/images/Fedora-Cloud-Base-Generic.x86_64-40-1.14.qcow2|fedora40|fedora|fedora"
    ["Fedora 41"]="fedora|41|41|https://download.fedoraproject.org/pub/fedora/linux/releases/41/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-41-1.4.x86_64.qcow2|fedora41|fedora|fedora"

    # RHEL-based - Enterprise Distributions
    ["CentOS Stream 9"]="centos|stream9|stream9|https://cloud.centos.org/centos/9-stream/x86_64/images/CentOS-Stream-GenericCloud-9-latest.x86_64.qcow2|centos9|centos|centos"
    ["AlmaLinux 9"]="almalinux|9|9|https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-latest.x86_64.qcow2|alma9|alma|alma"
    ["Rocky Linux 9"]="rockylinux|9|9|https://download.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud.latest.x86_64.qcow2|rocky9|rocky|rocky"

    # Arch Linux - Rolling Release
    ["Arch Linux (Rolling)"]="arch|rolling|latest|https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2|archlinux|arch|arch"

    # openSUSE
    ["openSUSE Leap 15.6"]="opensuse|15.6|leap156|https://download.opensuse.org/distribution/leap/15.6/appliances/openSUSE-Leap-15.6-Minimal-VM.x86_64-Cloud.qcow2|opensuse|opensuse|opensuse"
    ["openSUSE Tumbleweed"]="opensuse|tumbleweed|tumbleweed|https://download.opensuse.org/tumbleweed/appliances/openSUSE-Tumbleweed-Minimal-VM.x86_64-Cloud.qcow2|tumbleweed|opensuse|opensuse"

    # Oracle Linux
    ["Oracle Linux 9"]="oracle|9|ol9|https://yum.oracle.com/templates/OracleLinux/OL9/u4/x86_64/OL9U4_x86_64-kvm-b234.qcow2|oracle9|oracle|oracle"

    # Alpine Linux - Lightweight
    ["Alpine Linux 3.20"]="alpine|3.20|v3.20|https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/cloud/nocloud_alpine-3.20.3-x86_64-bios-cloudinit-r0.qcow2|alpine|alpine|alpine"
)

# Start the main menu
main_menu
