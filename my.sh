#!/bin/bash
set -euo pipefail

# =============================
# Enhanced Multi-VM Manager v2.0
# =============================

# Global variables
VERSION="2.0"
KVM_AVAILABLE=true

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

# Function to validate input
validate_input() {
    local type=$1
    local value=$2
    
    case $type in
        "number")
            if ! [[ "$value" =~ ^[0-9]+$ ]]; then
                print_status "ERROR" "Must be a number"
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
            if ! [[ "$value" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
                print_status "ERROR" "Username must start with a letter or underscore"
                return 1
            fi
            if [ ${#value} -gt 32 ]; then
                print_status "ERROR" "Username must be 32 characters or less"
                return 1
            fi
            ;;
        "password")
            if [ ${#value} -lt 4 ]; then
                print_status "ERROR" "Password must be at least 4 characters"
                return 1
            fi
            ;;
    esac
    return 0
}

# Function to check KVM availability
check_kvm() {
    if [[ -r /dev/kvm ]] && [[ -w /dev/kvm ]]; then
        KVM_AVAILABLE=true
        print_status "SUCCESS" "KVM acceleration available"
    else
        KVM_AVAILABLE=false
        print_status "WARN" "KVM not available - VMs will run slower (software emulation)"
        print_status "INFO" "To enable KVM: sudo usermod -aG kvm $USER && newgrp kvm"
    fi
}

# Function to check dependencies
check_dependencies() {
    local deps=("qemu-system-x86_64" "wget" "cloud-localds" "qemu-img" "openssl")
    local missing_deps=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_status "ERROR" "Missing dependencies: ${missing_deps[*]}"
        echo
        print_status "INFO" "Install on Ubuntu/Debian:"
        echo "  sudo apt update && sudo apt install -y qemu-system-x86 qemu-utils cloud-image-utils wget openssl"
        echo
        print_status "INFO" "Install on Fedora/CentOS/RHEL:"
        echo "  sudo dnf install -y qemu-kvm qemu-img cloud-utils wget openssl"
        echo
        print_status "INFO" "Install on Arch Linux:"
        echo "  sudo pacman -S qemu-full cloud-utils wget openssl"
        exit 1
    fi
    
    print_status "SUCCESS" "All dependencies are installed"
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
        # If no tool available, assume port is free
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
        find "$VM_DIR" -maxdepth 1 -name "*.conf" -exec basename {} .conf \; 2>/dev/null | sort
    fi
}

# Function to load VM configuration
load_vm_config() {
    local vm_name=$1
    local config_file="$VM_DIR/$vm_name.conf"
    
    if [[ -f "$config_file" ]]; then
        # Clear previous variables
        unset VM_NAME OS_TYPE OS_VERSION CODENAME IMG_URL HOSTNAME USERNAME PASSWORD
        unset DISK_SIZE MEMORY CPUS SSH_PORT GUI_MODE PORT_FORWARDS IMG_FILE SEED_FILE CREATED
        
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
    
    # Secure the config file
    chmod 600 "$config_file"
    print_status "SUCCESS" "Configuration saved to $config_file"
}

# Function to detect image format
detect_image_format() {
    local img_file=$1
    qemu-img info "$img_file" 2>/dev/null | grep "file format:" | awk '{print $3}'
}

# Function to download image with progress
download_image() {
    local url=$1
    local output=$2
    
    print_status "INFO" "Downloading image..."
    print_status "INFO" "URL: $url"
    
    if wget --progress=bar:force:noscroll -O "$output.tmp" "$url" 2>&1; then
        mv "$output.tmp" "$output"
        print_status "SUCCESS" "Download completed"
        return 0
    else
        rm -f "$output.tmp"
        print_status "ERROR" "Download failed"
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
    
    # Sort and display OS options
    while IFS= read -r os; do
        os_keys+=("$os")
        printf "  %2d) %s\n" "$i" "$os"
        ((i++))
    done < <(printf '%s\n' "${!OS_OPTIONS[@]}" | sort)
    
    echo
    
    while true; do
        read -p "$(print_status "INPUT" "Enter your choice (1-${#os_keys[@]}): ")" choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#os_keys[@]} ]; then
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

    # Username
    while true; do
        read -p "$(print_status "INPUT" "Enter username (default: $DEFAULT_USERNAME): ")" USERNAME
        USERNAME="${USERNAME:-$DEFAULT_USERNAME}"
        if validate_input "username" "$USERNAME"; then
            break
        fi
    done

    # Password
    while true; do
        read -s -p "$(print_status "INPUT" "Enter password (default: $DEFAULT_PASSWORD): ")" PASSWORD
        echo
        PASSWORD="${PASSWORD:-$DEFAULT_PASSWORD}"
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
            if [ "$MEMORY" -lt 512 ]; then
                print_status "WARN" "Less than 512MB RAM may cause issues"
            fi
            break
        fi
    done

    # CPUs
    local max_cpus
    max_cpus=$(nproc 2>/dev/null || echo 4)
    while true; do
        read -p "$(print_status "INPUT" "Number of CPUs (default: 2, max: $max_cpus): ")" CPUS
        CPUS="${CPUS:-2}"
        if validate_input "number" "$CPUS"; then
            if [ "$CPUS" -gt "$max_cpus" ]; then
                print_status "WARN" "Reducing CPUs to maximum available: $max_cpus"
                CPUS="$max_cpus"
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

    # Set file paths
    IMG_FILE="$VM_DIR/$VM_NAME.qcow2"
    SEED_FILE="$VM_DIR/$VM_NAME-seed.iso"
    CREATED="$(date '+%Y-%m-%d %H:%M:%S')"

    echo
    print_status "INFO" "VM Configuration Summary:"
    echo "  Name: $VM_NAME"
    echo "  OS: $OS_TYPE $OS_VERSION ($CODENAME)"
    echo "  Hostname: $HOSTNAME"
    echo "  Username: $USERNAME"
    echo "  Disk: $DISK_SIZE | RAM: ${MEMORY}MB | CPUs: $CPUS"
    echo "  SSH Port: $SSH_PORT"
    echo "  GUI Mode: $GUI_MODE"
    echo "  Port Forwards: ${PORT_FORWARDS:-None}"
    echo
    
    read -p "$(print_status "INPUT" "Proceed with creation? (Y/n): ")" confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        print_status "INFO" "VM creation cancelled"
        return 1
    fi

    # Download and setup VM image
    setup_vm_image
    
    # Save configuration
    save_vm_config
    
    echo
    print_status "SUCCESS" "VM '$VM_NAME' created successfully!"
    print_status "INFO" "Start it with option 2 from the main menu"
}

# Function to setup VM image
setup_vm_image() {
    print_status "INFO" "Setting up VM image..."
    
    # Create VM directory if it doesn't exist
    mkdir -p "$VM_DIR"
    
    # Download base image if needed
    local base_img="$VM_DIR/base-${OS_TYPE}-${CODENAME}.img"
    
    if [[ ! -f "$base_img" ]]; then
        if ! download_image "$IMG_URL" "$base_img"; then
            print_status "ERROR" "Failed to download base image"
            exit 1
        fi
    else
        print_status "INFO" "Using cached base image: $base_img"
    fi
    
    # Detect format of downloaded image
    local img_format
    img_format=$(detect_image_format "$base_img")
    img_format="${img_format:-qcow2}"
    
    print_status "INFO" "Creating VM disk from base image..."
    
    # Create a new disk based on the downloaded image
    if [[ -f "$IMG_FILE" ]]; then
        print_status "WARN" "Disk image already exists, overwriting..."
        rm -f "$IMG_FILE"
    fi
    
    # Create overlay disk with backing file
    if ! qemu-img create -f qcow2 -F "$img_format" -b "$base_img" "$IMG_FILE" "$DISK_SIZE" 2>/dev/null; then
        # Fallback: copy and resize
        print_status "INFO" "Using fallback method (copy and resize)..."
        cp "$base_img" "$IMG_FILE"
        qemu-img resize "$IMG_FILE" "$DISK_SIZE" 2>/dev/null || true
    fi
    
    print_status "SUCCESS" "Disk image created: $IMG_FILE"

    # Create cloud-init configuration
    print_status "INFO" "Creating cloud-init configuration..."
    
    # Generate password hash
    local password_hash
    password_hash=$(openssl passwd -6 "$PASSWORD" 2>/dev/null) || \
    password_hash=$(openssl passwd -1 "$PASSWORD" 2>/dev/null)
    
    cat > user-data <<EOF
#cloud-config
hostname: $HOSTNAME
fqdn: $HOSTNAME.local
manage_etc_hosts: true

users:
  - name: $USERNAME
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: sudo, adm, cdrom, dip, plugdev
    shell: /bin/bash
    lock_passwd: false
    passwd: $password_hash
    ssh_pwauth: true

chpasswd:
  expire: false
  users:
    - name: root
      password: $password_hash
      type: hash
    - name: $USERNAME
      password: $password_hash
      type: hash

ssh_pwauth: true
disable_root: false

# Enable password authentication for SSH
write_files:
  - path: /etc/ssh/sshd_config.d/99-allow-password.conf
    content: |
      PasswordAuthentication yes
      PermitRootLogin yes
    permissions: '0644'

runcmd:
  - systemctl restart sshd || systemctl restart ssh || true
  - echo "VM setup complete" > /var/log/cloud-init-complete.log

final_message: |
  Cloud-init has finished.
  VM: $VM_NAME
  Hostname: $HOSTNAME
  User: $USERNAME
  
  Login via: ssh -p $SSH_PORT $USERNAME@localhost
EOF

    cat > meta-data <<EOF
instance-id: iid-$VM_NAME-$(date +%s)
local-hostname: $HOSTNAME
EOF

    cat > network-config <<EOF
version: 2
ethernets:
  id0:
    match:
      driver: virtio
    dhcp4: true
EOF

    # Create seed ISO
    if ! cloud-localds -N network-config "$SEED_FILE" user-data meta-data 2>/dev/null; then
        # Fallback without network config
        if ! cloud-localds "$SEED_FILE" user-data meta-data; then
            print_status "ERROR" "Failed to create cloud-init seed image"
            cleanup
            exit 1
        fi
    fi
    
    # Cleanup temporary files
    cleanup
    
    print_status "SUCCESS" "Cloud-init configuration created"
}

# Function to build QEMU command
build_qemu_command() {
    local vm_name=$1
    
    QEMU_CMD=(qemu-system-x86_64)
    
    # Add KVM if available
    if $KVM_AVAILABLE; then
        QEMU_CMD+=(-enable-kvm -cpu host)
    else
        QEMU_CMD+=(-cpu qemu64)
    fi
    
    # Basic configuration
    QEMU_CMD+=(
        -name "$vm_name"
        -m "$MEMORY"
        -smp "$CPUS"
        -drive "file=$IMG_FILE,format=qcow2,if=virtio,cache=writeback"
        -drive "file=$SEED_FILE,format=raw,if=virtio,readonly=on"
        -boot order=c
    )
    
    # Build network configuration with all port forwards
    local netdev_opts="user,id=net0,hostfwd=tcp::${SSH_PORT}-:22"
    
    if [[ -n "$PORT_FORWARDS" ]]; then
        IFS=',' read -ra forwards <<< "$PORT_FORWARDS"
        for forward in "${forwards[@]}"; do
            forward=$(echo "$forward" | tr -d ' ')
            if [[ "$forward" =~ ^[0-9]+:[0-9]+$ ]]; then
                IFS=':' read -r host_port guest_port <<< "$forward"
                netdev_opts+=",hostfwd=tcp::${host_port}-:${guest_port}"
            fi
        done
    fi
    
    QEMU_CMD+=(
        -device virtio-net-pci,netdev=net0
        -netdev "$netdev_opts"
    )
    
    # Display configuration
    if [[ "$GUI_MODE" == true ]]; then
        QEMU_CMD+=(-vga virtio -display gtk,gl=on)
    else
        QEMU_CMD+=(-nographic -serial mon:stdio)
    fi
    
    # Performance enhancements
    QEMU_CMD+=(
        -device virtio-balloon-pci,id=balloon0
        -object rng-random,filename=/dev/urandom,id=rng0
        -device virtio-rng-pci,rng=rng0
    )
    
    # Machine type for better compatibility
    QEMU_CMD+=(-machine type=q35,accel=kvm:tcg)
}

# Function to start a VM
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
    echo "========================================"
    echo "  OS: $OS_TYPE $OS_VERSION"
    echo "  SSH: ssh -p $SSH_PORT $USERNAME@localhost"
    echo "  Password: $PASSWORD"
    if [[ -n "$PORT_FORWARDS" ]]; then
        echo "  Port Forwards: $PORT_FORWARDS"
    fi
    echo "========================================"
    echo
    
    if [[ "$GUI_MODE" == false ]]; then
        print_status "INFO" "Console mode - Press Ctrl+A, X to exit"
    fi
    
    # Build and execute QEMU command
    build_qemu_command "$vm_name"
    
    print_status "INFO" "Launching QEMU..."
    echo
    
    "${QEMU_CMD[@]}"
    
    echo
    print_status "INFO" "VM '$vm_name' has been shut down"
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
    
    if ! is_port_available "$SSH_PORT"; then
        print_status "ERROR" "SSH port $SSH_PORT is already in use"
        return 1
    fi
    
    build_qemu_command "$vm_name"
    
    # Replace display options for background mode
    local bg_cmd=()
    for arg in "${QEMU_CMD[@]}"; do
        case "$arg" in
            -nographic|-serial|mon:stdio|-display|gtk*) continue ;;
            *) bg_cmd+=("$arg") ;;
        esac
    done
    
    bg_cmd+=(-daemonize -display none -monitor none -serial none)
    
    print_status "INFO" "Starting VM '$vm_name' in background..."
    
    if "${bg_cmd[@]}"; then
        sleep 2
        if is_vm_running "$vm_name"; then
            print_status "SUCCESS" "VM '$vm_name' started in background"
            print_status "INFO" "SSH: ssh -p $SSH_PORT $USERNAME@localhost"
        else
            print_status "ERROR" "VM failed to start"
            return 1
        fi
    else
        print_status "ERROR" "Failed to start VM"
        return 1
    fi
}

# Function to check if VM is running
is_vm_running() {
    local vm_name=$1
    pgrep -f "qemu-system-x86_64.*-name $vm_name" >/dev/null 2>&1
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
    
    # Try graceful shutdown first
    if pkill -TERM -f "qemu-system-x86_64.*-name $vm_name" 2>/dev/null; then
        local count=0
        while is_vm_running "$vm_name" && [ $count -lt 10 ]; do
            sleep 1
            ((count++))
            echo -n "."
        done
        echo
    fi
    
    # Force kill if still running
    if is_vm_running "$vm_name"; then
        print_status "WARN" "VM did not stop gracefully, forcing termination..."
        pkill -9 -f "qemu-system-x86_64.*-name $vm_name" 2>/dev/null
        sleep 1
    fi
    
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
    echo "  - $IMG_FILE"
    echo "  - $SEED_FILE"
    echo "  - $VM_DIR/$vm_name.conf"
    echo
    
    read -p "$(print_status "INPUT" "Type 'DELETE' to confirm: ")" confirm
    
    if [[ "$confirm" == "DELETE" ]]; then
        rm -f "$IMG_FILE" "$SEED_FILE" "$VM_DIR/$vm_name.conf"
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
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    VM Information                            ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    printf "║  %-15s: %-44s ║\n" "Name" "$VM_NAME"
    printf "║  %-15s: ${status_color}%-44s\033[0m ║\n" "Status" "$status"
    printf "║  %-15s: %-44s ║\n" "OS" "$OS_TYPE $OS_VERSION"
    printf "║  %-15s: %-44s ║\n" "Codename" "$CODENAME"
    printf "║  %-15s: %-44s ║\n" "Hostname" "$HOSTNAME"
    printf "║  %-15s: %-44s ║\n" "Username" "$USERNAME"
    printf "║  %-15s: %-44s ║\n" "Password" "$PASSWORD"
    echo "╠══════════════════════════════════════════════════════════════╣"
    printf "║  %-15s: %-44s ║\n" "SSH Port" "$SSH_PORT"
    printf "║  %-15s: %-44s ║\n" "Memory" "${MEMORY} MB"
    printf "║  %-15s: %-44s ║\n" "CPUs" "$CPUS"
    printf "║  %-15s: %-44s ║\n" "Disk Size" "$DISK_SIZE"
    printf "║  %-15s: %-44s ║\n" "GUI Mode" "$GUI_MODE"
    printf "║  %-15s: %-44s ║\n" "Port Forwards" "${PORT_FORWARDS:-None}"
    echo "╠══════════════════════════════════════════════════════════════╣"
    printf "║  %-15s: %-44s ║\n" "Created" "$CREATED"
    echo "╚══════════════════════════════════════════════════════════════╝"
    
    if [[ -f "$IMG_FILE" ]]; then
        local disk_actual
        disk_actual=$(du -h "$IMG_FILE" 2>/dev/null | cut -f1)
        echo
        echo "Disk Usage: $disk_actual (actual) / $DISK_SIZE (allocated)"
    fi
    
    echo
    print_status "INFO" "Quick SSH command:"
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
    
    if is_vm_running "$vm_name"; then
        print_status "WARN" "VM is running. Some changes will only apply after restart."
    fi
    
    while true; do
        echo
        print_status "INFO" "Editing VM: $vm_name"
        echo "╔═══════════════════════════════════════╗"
        echo "║          Configuration Options        ║"
        echo "╠═══════════════════════════════════════╣"
        echo "║  1) Hostname      : $HOSTNAME"
        echo "║  2) Username      : $USERNAME"
        echo "║  3) Password      : ****"
        echo "║  4) SSH Port      : $SSH_PORT"
        echo "║  5) Memory (MB)   : $MEMORY"
        echo "║  6) CPU Count     : $CPUS"
        echo "║  7) GUI Mode      : $GUI_MODE"
        echo "║  8) Port Forwards : ${PORT_FORWARDS:-None}"
        echo "╠═══════════════════════════════════════╣"
        echo "║  0) Back to main menu                 ║"
        echo "╚═══════════════════════════════════════╝"
        
        read -p "$(print_status "INPUT" "Enter your choice: ")" edit_choice
        
        local need_rebuild=false
        
        case $edit_choice in
            1)
                while true; do
                    read -p "$(print_status "INPUT" "New hostname: ")" new_val
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
                    read -p "$(print_status "INPUT" "New username: ")" new_val
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
                    read -p "$(print_status "INPUT" "New SSH port: ")" new_val
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
                    read -p "$(print_status "INPUT" "New memory (MB): ")" new_val
                    new_val="${new_val:-$MEMORY}"
                    if validate_input "number" "$new_val"; then
                        MEMORY="$new_val"
                        break
                    fi
                done
                ;;
            6)
                while true; do
                    read -p "$(print_status "INPUT" "New CPU count: ")" new_val
                    new_val="${new_val:-$CPUS}"
                    if validate_input "number" "$new_val"; then
                        CPUS="$new_val"
                        break
                    fi
                done
                ;;
            7)
                if [[ "$GUI_MODE" == true ]]; then
                    GUI_MODE=false
                else
                    GUI_MODE=true
                fi
                print_status "SUCCESS" "GUI mode set to: $GUI_MODE"
                ;;
            8)
                read -p "$(print_status "INPUT" "Port forwards (e.g., 8080:80,3000:3000): ")" PORT_FORWARDS
                ;;
            0)
                return 0
                ;;
            *)
                print_status "ERROR" "Invalid selection"
                continue
                ;;
        esac
        
        # Rebuild cloud-init if needed
        if $need_rebuild; then
            print_status "INFO" "Rebuilding cloud-init configuration..."
            setup_vm_image
        fi
        
        save_vm_config
        print_status "SUCCESS" "Configuration updated"
    done
}

# Function to clone a VM
clone_vm() {
    local source_vm=$1
    
    if ! load_vm_config "$source_vm"; then
        return 1
    fi
    
    if is_vm_running "$source_vm"; then
        print_status "WARN" "Cloning a running VM may result in inconsistent state"
        read -p "$(print_status "INPUT" "Continue anyway? (y/N): ")" confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            return 1
        fi
    fi
    
    local source_name="$VM_NAME"
    local source_img="$IMG_FILE"
    
    while true; do
        read -p "$(print_status "INPUT" "Enter name for cloned VM: ")" new_name
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
    
    if ! validate_input "name" "$snapshot_name"; then
        return 1
    fi
    
    print_status "INFO" "Creating snapshot '$snapshot_name'..."
    
    if qemu-img snapshot -c "$snapshot_name" "$IMG_FILE"; then
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
    
    print_status "INFO" "Snapshots for VM '$vm_name':"
    echo
    qemu-img snapshot -l "$IMG_FILE" 2>/dev/null || echo "No snapshots found"
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
    
    print_status "INFO" "Available snapshots:"
    qemu-img snapshot -l "$IMG_FILE" 2>/dev/null || {
        print_status "ERROR" "No snapshots found"
        return 1
    }
    
    echo
    read -p "$(print_status "INPUT" "Enter snapshot name to restore: ")" snapshot_name
    
    print_status "WARN" "This will restore VM to snapshot '$snapshot_name'"
    read -p "$(print_status "INPUT" "Are you sure? (y/N): ")" confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        if qemu-img snapshot -a "$snapshot_name" "$IMG_FILE"; then
            print_status "SUCCESS" "Snapshot '$snapshot_name' restored"
        else
            print_status "ERROR" "Failed to restore snapshot"
            return 1
        fi
    fi
}

# Function to delete snapshot
delete_snapshot() {
    local vm_name=$1
    
    if ! load_vm_config "$vm_name"; then
        return 1
    fi
    
    print_status "INFO" "Available snapshots:"
    qemu-img snapshot -l "$IMG_FILE" 2>/dev/null || {
        print_status "ERROR" "No snapshots found"
        return 1
    }
    
    echo
    read -p "$(print_status "INPUT" "Enter snapshot name to delete: ")" snapshot_name
    
    if qemu-img snapshot -d "$snapshot_name" "$IMG_FILE"; then
        print_status "SUCCESS" "Snapshot '$snapshot_name' deleted"
    else
        print_status "ERROR" "Failed to delete snapshot"
        return 1
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
    
    print_status "INFO" "Current disk size: $DISK_SIZE"
    
    # Get actual disk info
    qemu-img info "$IMG_FILE" 2>/dev/null | grep -E "virtual size|disk size"
    echo
    
    while true; do
        read -p "$(print_status "INPUT" "Enter new disk size (e.g., 50G): ")" new_size
        if validate_input "size" "$new_size"; then
            break
        fi
    done
    
    print_status "WARN" "Shrinking disk is not supported. Only expansion is allowed."
    read -p "$(print_status "INPUT" "Proceed with resize to $new_size? (y/N): ")" confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        if qemu-img resize "$IMG_FILE" "$new_size"; then
            DISK_SIZE="$new_size"
            save_vm_config
            print_status "SUCCESS" "Disk resized to $new_size"
            print_status "INFO" "You may need to extend the filesystem inside the VM"
        else
            print_status "ERROR" "Failed to resize disk"
            return 1
        fi
    fi
}

# Function to show system info
show_system_info() {
    echo
    print_status "INFO" "System Information"
    echo "══════════════════════════════════════════"
    echo "Hostname: $(hostname)"
    echo "Kernel: $(uname -r)"
    echo "CPU: $(nproc) cores"
    echo "Memory: $(free -h | awk '/^Mem:/ {print $2}') total"
    echo "Disk (VM dir): $(df -h "$VM_DIR" 2>/dev/null | awk 'NR==2 {print $4}') available"
    echo "KVM Available: $KVM_AVAILABLE"
    echo "VM Directory: $VM_DIR"
    echo "══════════════════════════════════════════"
    echo
    read -p "$(print_status "INPUT" "Press Enter to continue...")"
}

# Snapshot submenu
snapshot_menu() {
    local vm_name=$1
    
    while true; do
        echo
        print_status "INFO" "Snapshot Management: $vm_name"
        echo "  1) Create snapshot"
        echo "  2) List snapshots"
        echo "  3) Restore snapshot"
        echo "  4) Delete snapshot"
        echo "  0) Back"
        
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
    local vms=("${@:2}")
    local vm_count=${#vms[@]}
    
    if [ $vm_count -eq 0 ]; then
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
        
        local vms
        mapfile -t vms < <(get_vm_list)
        local vm_count=${#vms[@]}
        
        if [ "$vm_count" -gt 0 ]; then
            print_status "INFO" "Existing VMs ($vm_count):"
            echo
            for i in "${!vms[@]}"; do
                local status="○ Stopped"
                local status_color="\033[1;31m"
                if is_vm_running "${vms[$i]}"; then
                    status="● Running"
                    status_color="\033[1;32m"
                fi
                printf "  %2d) %-25s ${status_color}%s\033[0m\n" "$((i+1))" "${vms[$i]}" "$status"
            done
            echo
        else
            print_status "INFO" "No VMs found. Create one to get started!"
            echo
        fi
        
        echo "╔═══════════════════════════════════════╗"
        echo "║             Main Menu                 ║"
        echo "╠═══════════════════════════════════════╣"
        echo "║  1) Create new VM                     ║"
        if [ "$vm_count" -gt 0 ]; then
        echo "║  2) Start VM                          ║"
        echo "║  3) Start VM (background)             ║"
        echo "║  4) Stop VM                           ║"
        echo "║  5) Show VM info                      ║"
        echo "║  6) Edit VM configuration             ║"
        echo "║  7) Clone VM                          ║"
        echo "║  8) Snapshot management               ║"
        echo "║  9) Resize VM disk                    ║"
        echo "║ 10) Delete VM                         ║"
        fi
        echo "╠═══════════════════════════════════════╣"
        echo "║  s) System info                       ║"
        echo "║  0) Exit                              ║"
        echo "╚═══════════════════════════════════════╝"
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

# Supported OS list with LATEST versions (Updated 2024)
declare -A OS_OPTIONS=(
    # Ubuntu - Latest LTS and Latest Release
    ["Ubuntu 24.04 LTS (Noble)"]="ubuntu|24.04|noble|https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img|ubuntu24|ubuntu|ubuntu"
    ["Ubuntu 24.10 (Oracular)"]="ubuntu|24.10|oracular|https://cloud-images.ubuntu.com/oracular/current/oracular-server-cloudimg-amd64.img|ubuntu24|ubuntu|ubuntu"
    
    # Debian - Latest Stable
    ["Debian 12 (Bookworm)"]="debian|12|bookworm|https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2|debian12|debian|debian"
    ["Debian 13 (Trixie/Testing)"]="debian|13|trixie|https://cloud.debian.org/images/cloud/trixie/daily/latest/debian-13-generic-amd64-daily.qcow2|debian13|debian|debian"
    
    # Fedora - Latest
    ["Fedora 41"]="fedora|41|41|https://download.fedoraproject.org/pub/fedora/linux/releases/41/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-41-1.4.x86_64.qcow2|fedora41|fedora|fedora"
    
    # RHEL-based - Latest
    ["CentOS Stream 9"]="centos|stream9|stream9|https://cloud.centos.org/centos/9-stream/x86_64/images/CentOS-Stream-GenericCloud-9-latest.x86_64.qcow2|centos9|centos|centos"
    ["AlmaLinux 9"]="almalinux|9|9|https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-latest.x86_64.qcow2|alma9|alma|alma"
    ["Rocky Linux 9"]="rockylinux|9|9|https://download.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud.latest.x86_64.qcow2|rocky9|rocky|rocky"
    
    # Arch Linux - Rolling Release
    ["Arch Linux (Latest)"]="arch|rolling|latest|https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2|archlinux|arch|arch"
    
    # openSUSE - Latest
    ["openSUSE Leap 15.6"]="opensuse|15.6|leap|https://download.opensuse.org/distribution/leap/15.6/appliances/openSUSE-Leap-15.6-Minimal-VM.x86_64-Cloud.qcow2|opensuse|opensuse|opensuse"
    ["openSUSE Tumbleweed"]="opensuse|tumbleweed|tumbleweed|https://download.opensuse.org/tumbleweed/appliances/openSUSE-Tumbleweed-Minimal-VM.x86_64-Cloud.qcow2|tumbleweed|opensuse|opensuse"
    
    # Oracle Linux - Latest
    ["Oracle Linux 9"]="oracle|9|9|https://yum.oracle.com/templates/OracleLinux/OL9/u4/x86_64/OL9U4_x86_64-kvm-b234.qcow2|oracle9|oracle|oracle"
)

# Start the main menu
main_menu
