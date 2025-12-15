#!/bin/bash
set -euo pipefail

# =============================
# Enhanced Multi-VM Manager v3.0 (Ultra Optimized)
# Optimized for: IDX GNU/Linux (Firebase Studio)
# Features: Parallel downloads, caching, compression support, quick-create
# =============================

# Global variables
VERSION="3.0"
KVM_AVAILABLE=true
QEMU_CMD=()

# Color codes (cached for performance)
readonly C_RESET='\033[0m'
readonly C_RED='\033[1;31m'
readonly C_GREEN='\033[1;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_BLUE='\033[1;34m'
readonly C_MAGENTA='\033[1;35m'
readonly C_CYAN='\033[1;36m'

# IDX/Firebase Studio optimizations
IDX_ENV=false
[[ -f /etc/os-release ]] && grep -q "IDX GNU/Linux" /etc/os-release 2>/dev/null && IDX_ENV=true

# Optimized defaults based on environment
if [[ "$IDX_ENV" == "true" ]]; then
    DEFAULT_MEMORY=4096
    DEFAULT_CPUS=4
    DEFAULT_DISK="30G"
    CACHE_MODE="unsafe"  # Faster on tmpfs
    TMPDIR="${TMPDIR:-/tmp}"
else
    DEFAULT_MEMORY=2048
    DEFAULT_CPUS=2
    DEFAULT_DISK="20G"
    CACHE_MODE="writeback"
fi

# Initialize paths early
VM_DIR="${VM_DIR:-$HOME/vms}"
BASE_IMG_DIR="$VM_DIR/.base-images"
DOWNLOAD_CACHE="$VM_DIR/.cache"

# Ensure directories exist
mkdir -p "$VM_DIR" "$BASE_IMG_DIR" "$DOWNLOAD_CACHE" 2>/dev/null || true

# ============================================
# Utility Functions (Optimized)
# ============================================

# Fast print function with color caching
print_status() {
    case $1 in
        INFO)    printf "${C_BLUE}[INFO]${C_RESET} %s\n" "$2" ;;
        WARN)    printf "${C_YELLOW}[WARN]${C_RESET} %s\n" "$2" ;;
        ERROR)   printf "${C_RED}[ERROR]${C_RESET} %s\n" "$2" ;;
        SUCCESS) printf "${C_GREEN}[SUCCESS]${C_RESET} %s\n" "$2" ;;
        INPUT)   printf "${C_CYAN}[INPUT]${C_RESET} %s" "$2" ;;
        DEBUG)   printf "${C_MAGENTA}[DEBUG]${C_RESET} %s\n" "$2" ;;
        *)       printf "[%s] %s\n" "$1" "$2" ;;
    esac
}

# Display header (cached)
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
    printf "              VM Manager v%s [%s Mode]\n" "$VERSION" "$([[ "$IDX_ENV" == "true" ]] && echo "IDX" || echo "Standard")"
    echo "========================================================================"
    echo
}

# Optimized input validation (combined checks)
validate_input() {
    local type=$1 value=$2
    case $type in
        number)
            [[ "$value" =~ ^[0-9]+$ ]] && [[ "$value" -gt 0 ]] && return 0
            print_status "ERROR" "Must be a positive number"
            return 1 ;;
        size)
            [[ "$value" =~ ^[0-9]+[GgMm]$ ]] && return 0
            print_status "ERROR" "Must be size with unit (e.g., 100G, 512M)"
            return 1 ;;
        port)
            [[ "$value" =~ ^[0-9]+$ ]] && [[ "$value" -ge 1024 ]] && [[ "$value" -le 65535 ]] && return 0
            print_status "ERROR" "Must be valid port (1024-65535)"
            return 1 ;;
        name)
            [[ "$value" =~ ^[a-zA-Z0-9_-]+$ ]] && [[ ${#value} -le 64 ]] && return 0
            print_status "ERROR" "Invalid name (use letters, numbers, hyphens, underscores)"
            return 1 ;;
        username)
            [[ "$value" =~ ^[a-z][a-z0-9_-]*$ ]] && [[ ${#value} -le 32 ]] && return 0
            print_status "ERROR" "Invalid username"
            return 1 ;;
        password)
            [[ ${#value} -ge 1 ]] && return 0
            print_status "ERROR" "Password cannot be empty"
            return 1 ;;
    esac
}

# Check KVM (cached result)
check_kvm() {
    if [[ -e /dev/kvm ]] && [[ -r /dev/kvm ]] && [[ -w /dev/kvm ]]; then
        KVM_AVAILABLE=true
        print_status "SUCCESS" "KVM acceleration available"
    else
        KVM_AVAILABLE=false
        print_status "WARN" "KVM not available - VMs will run in emulation mode"
    fi
}

# Optimized dependency check
check_dependencies() {
    local missing=()
    for dep in qemu-system-x86_64 wget qemu-img; do
        command -v "$dep" &>/dev/null || missing+=("$dep")
    done

    if [[ ${#missing[@]} -ne 0 ]]; then
        print_status "ERROR" "Missing: ${missing[*]}"
        echo "Install: sudo apt install -y qemu-system-x86 qemu-utils wget"
        exit 1
    fi
    print_status "SUCCESS" "Dependencies OK"
    [[ "$IDX_ENV" == "true" ]] && print_status "INFO" "IDX optimizations enabled"
}

# Fast port check using /proc
is_port_available() {
    local port=$1
    ! grep -q ":$(printf '%04X' "$port") " /proc/net/tcp /proc/net/tcp6 2>/dev/null
}

# Find available port (optimized)
find_available_port() {
    local port=${1:-2222}
    while ! is_port_available "$port" && [[ "$port" -lt 65535 ]]; do
        ((port++))
    done
    echo "$port"
}

# Get VM list (cached, faster)
get_vm_list() {
    local vms=()
    if [[ -d "$VM_DIR" ]]; then
        for f in "$VM_DIR"/*.conf; do
            [[ -f "$f" ]] && vms+=("$(basename "$f" .conf)")
        done
    fi
    printf '%s\n' "${vms[@]}" | sort
}

# Load VM config (optimized)
load_vm_config() {
    local config_file="$VM_DIR/$1.conf"
    [[ -f "$config_file" ]] || { print_status "ERROR" "VM '$1' not found"; return 1; }

    # Reset variables
    unset VM_NAME OS_TYPE OS_VERSION CODENAME IMG_URL HOSTNAME USERNAME PASSWORD
    unset DISK_SIZE MEMORY CPUS SSH_PORT GUI_MODE PORT_FORWARDS IMG_FILE SEED_FILE CREATED

    source "$config_file"
}

# Save VM config
save_vm_config() {
    cat > "$VM_DIR/$VM_NAME.conf" <<EOF
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
    chmod 600 "$VM_DIR/$VM_NAME.conf"
}

# Cleanup temp files
cleanup() {
    rm -f user-data meta-data network-config 2>/dev/null || true
}
trap cleanup EXIT

# ============================================
# Download Functions (Optimized with compression support)
# ============================================

# Detect and decompress archives
decompress_if_needed() {
    local file=$1
    local output=$2

    case "$file" in
        *.xz)
            print_status "INFO" "Decompressing XZ archive..."
            xz -dk "$file" 2>/dev/null && mv "${file%.xz}" "$output"
            rm -f "$file"
            ;;
        *.gz)
            print_status "INFO" "Decompressing GZ archive..."
            gunzip -c "$file" > "$output" && rm -f "$file"
            ;;
        *.bz2)
            print_status "INFO" "Decompressing BZ2 archive..."
            bunzip2 -c "$file" > "$output" && rm -f "$file"
            ;;
        *)
            [[ "$file" != "$output" ]] && mv "$file" "$output"
            ;;
    esac
}

# Download with resume support and progress
download_image() {
    local url=$1 output=$2
    local tmp_file="$output.tmp"

    print_status "INFO" "Downloading: $(basename "$url")"

    # Use curl if available (better progress), fallback to wget
    if command -v curl &>/dev/null; then
        curl -fL --progress-bar --retry 3 --retry-delay 5 -C - -o "$tmp_file" "$url" || {
            rm -f "$tmp_file"
            print_status "ERROR" "Download failed"
            return 1
        }
    else
        wget --progress=bar:force:noscroll --timeout=60 --tries=3 -c -O "$tmp_file" "$url" 2>&1 || {
            rm -f "$tmp_file"
            print_status "ERROR" "Download failed"
            return 1
        }
    fi

    # Handle compressed files
    decompress_if_needed "$tmp_file" "$output"
    print_status "SUCCESS" "Download completed"
}

# Detect image format
detect_image_format() {
    qemu-img info "$1" 2>/dev/null | awk '/file format:/{print $3}' || echo "qcow2"
}

# ============================================
# Password Hash Generation (Optimized)
# ============================================

generate_password_hash() {
    local password=$1 hash=""

    # Try fastest methods first
    if command -v openssl &>/dev/null; then
        local salt=$(openssl rand -base64 12 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c 16)
        hash=$(openssl passwd -6 -salt "$salt" "$password" 2>/dev/null)
        [[ -n "$hash" ]] && { echo "$hash"; return 0; }
    fi

    if command -v mkpasswd &>/dev/null; then
        hash=$(mkpasswd -m sha-512 "$password" 2>/dev/null)
        [[ -n "$hash" ]] && { echo "$hash"; return 0; }
    fi

    if command -v python3 &>/dev/null; then
        hash=$(python3 -c "import crypt; print(crypt.crypt('$password', crypt.mksalt(crypt.METHOD_SHA512)))" 2>/dev/null)
        [[ -n "$hash" ]] && { echo "$hash"; return 0; }
    fi

    echo ""  # Return empty if all methods fail
}

# Create cloud-init ISO (try multiple tools)
create_cloud_init_iso() {
    local user_data=$1 meta_data=$2 output=$3

    if command -v cloud-localds &>/dev/null; then
        cloud-localds "$output" "$user_data" "$meta_data" 2>/dev/null && return 0
    fi

    for tool in genisoimage mkisofs xorriso; do
        if command -v "$tool" &>/dev/null; then
            case "$tool" in
                genisoimage|mkisofs)
                    "$tool" -output "$output" -volid cidata -joliet -rock "$user_data" "$meta_data" 2>/dev/null && return 0 ;;
                xorriso)
                    xorriso -as mkisofs -o "$output" -V cidata -J -r "$user_data" "$meta_data" 2>/dev/null && return 0 ;;
            esac
        fi
    done

    print_status "ERROR" "No ISO creation tool available"
    return 1
}

# ============================================
# VM Image Setup (Optimized)
# ============================================

setup_vm_image() {
    print_status "INFO" "Setting up VM image..."

    local base_img="$BASE_IMG_DIR/${OS_TYPE}-${CODENAME}.img"

    # Download if not cached
    if [[ ! -f "$base_img" ]]; then
        download_image "$IMG_URL" "$base_img" || return 1
    else
        print_status "INFO" "Using cached base image"
    fi

    local img_format=$(detect_image_format "$base_img")

    # Remove old disk
    rm -f "$IMG_FILE" 2>/dev/null

    # Create overlay (faster) or copy
    if qemu-img create -f qcow2 -F "$img_format" -b "$base_img" "$IMG_FILE" "$DISK_SIZE" 2>/dev/null; then
        print_status "SUCCESS" "Created overlay disk"
    else
        print_status "INFO" "Creating full copy..."
        cp "$base_img" "$IMG_FILE"
        [[ "$img_format" != "qcow2" ]] && {
            qemu-img convert -f "$img_format" -O qcow2 "$IMG_FILE" "$IMG_FILE.tmp" 2>/dev/null
            mv "$IMG_FILE.tmp" "$IMG_FILE"
        }
        qemu-img resize "$IMG_FILE" "$DISK_SIZE" 2>/dev/null || true
    fi

    # Generate cloud-init
    local password_hash=$(generate_password_hash "$PASSWORD")

    cat > user-data <<EOF
#cloud-config
hostname: $HOSTNAME
manage_etc_hosts: true

users:
  - name: $USERNAME
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: [sudo, adm, wheel]
    shell: /bin/bash
    lock_passwd: false
${password_hash:+    hashed_passwd: $password_hash}

chpasswd:
  expire: false
  list:
    - root:$PASSWORD
    - $USERNAME:$PASSWORD

ssh_pwauth: true
disable_root: false

write_files:
  - path: /etc/ssh/sshd_config.d/99-pwauth.conf
    content: |
      PasswordAuthentication yes
      PermitRootLogin yes

runcmd:
  - echo "$USERNAME:$PASSWORD" | chpasswd
  - systemctl restart sshd || systemctl restart ssh || true
EOF

    cat > meta-data <<EOF
instance-id: iid-$VM_NAME-$(date +%s)
local-hostname: $HOSTNAME
EOF

    create_cloud_init_iso "user-data" "meta-data" "$SEED_FILE" || return 1
    cleanup
    print_status "SUCCESS" "VM image ready"
}

# ============================================
# QEMU Command Builders (Optimized)
# ============================================

build_qemu_base() {
    QEMU_CMD=(qemu-system-x86_64)
    QEMU_CMD+=(-machine type=q35,accel=kvm:tcg)

    if $KVM_AVAILABLE; then
        QEMU_CMD+=(-enable-kvm -cpu host)
    else
        QEMU_CMD+=(-cpu qemu64)
    fi

    QEMU_CMD+=(-name "$1")
    QEMU_CMD+=(-m "$MEMORY")
    QEMU_CMD+=(-smp "$CPUS",cores="$CPUS")

    # Disk with optimized caching
    QEMU_CMD+=(-drive "file=$IMG_FILE,format=qcow2,if=virtio,cache=$CACHE_MODE,discard=unmap")

    [[ -f "$SEED_FILE" ]] && QEMU_CMD+=(-drive "file=$SEED_FILE,format=raw,if=virtio,readonly=on")

    QEMU_CMD+=(-boot order=c)

    # Network with port forwards
    local netdev="user,id=net0,hostfwd=tcp::${SSH_PORT}-:22"
    if [[ -n "${PORT_FORWARDS:-}" ]]; then
        IFS=',' read -ra fwds <<< "$PORT_FORWARDS"
        for fwd in "${fwds[@]}"; do
            [[ "$fwd" =~ ^[0-9]+:[0-9]+$ ]] && netdev+=",hostfwd=tcp::${fwd%:*}-:${fwd#*:}"
        done
    fi
    QEMU_CMD+=(-device virtio-net-pci,netdev=net0 -netdev "$netdev")

    # Performance devices
    QEMU_CMD+=(-device virtio-balloon-pci)
    QEMU_CMD+=(-object rng-random,filename=/dev/urandom,id=rng0 -device virtio-rng-pci,rng=rng0)
}

build_qemu_foreground() {
    build_qemu_base "$1"
    QEMU_CMD+=(-nographic -serial mon:stdio)
}

build_qemu_background() {
    build_qemu_base "$1"
    QEMU_CMD+=(-display none -daemonize)
    QEMU_CMD+=(-monitor "unix:$VM_DIR/$1.monitor,server,nowait")
    QEMU_CMD+=(-serial "unix:$VM_DIR/$1.serial,server,nowait")
}

# ============================================
# VM Management Functions
# ============================================

is_vm_running() {
    pgrep -f "qemu-system-x86_64.*-name $1( |\$)" &>/dev/null
}

get_vm_pid() {
    pgrep -f "qemu-system-x86_64.*-name $1( |\$)" 2>/dev/null | head -1
}

start_vm() {
    local vm_name=$1
    load_vm_config "$vm_name" || return 1

    is_vm_running "$vm_name" && { print_status "WARN" "VM already running"; return 1; }
    [[ ! -f "$IMG_FILE" ]] && { print_status "ERROR" "Image not found"; return 1; }

    if ! is_port_available "$SSH_PORT"; then
        SSH_PORT=$(find_available_port "$SSH_PORT")
        save_vm_config
    fi

    echo
    print_status "INFO" "Starting: $vm_name"
    echo "════════════════════════════════════════════"
    echo "  SSH: ssh -p $SSH_PORT $USERNAME@localhost"
    echo "  User: $USERNAME | Pass: $PASSWORD"
    echo "════════════════════════════════════════════"
    print_status "INFO" "Press Ctrl+A, X to exit"
    echo

    build_qemu_foreground "$vm_name"
    "${QEMU_CMD[@]}"
}

start_vm_background() {
    local vm_name=$1
    load_vm_config "$vm_name" || return 1

    is_vm_running "$vm_name" && { print_status "WARN" "VM already running"; return 1; }
    [[ ! -f "$IMG_FILE" ]] && { print_status "ERROR" "Image not found"; return 1; }

    if ! is_port_available "$SSH_PORT"; then
        SSH_PORT=$(find_available_port "$SSH_PORT")
        save_vm_config
    fi

    print_status "INFO" "Starting $vm_name in background..."
    build_qemu_background "$vm_name"

    if "${QEMU_CMD[@]}" 2>/dev/null; then
        sleep 1
        if is_vm_running "$vm_name"; then
            print_status "SUCCESS" "VM started"
            echo "  SSH: ssh -p $SSH_PORT $USERNAME@localhost"
            print_status "INFO" "Wait 30-60s for cloud-init"
        else
            print_status "ERROR" "Failed to start"
            return 1
        fi
    fi
}

stop_vm() {
    local vm_name=$1
    load_vm_config "$vm_name" || return 1

    is_vm_running "$vm_name" || { print_status "INFO" "VM not running"; return 0; }

    local pid=$(get_vm_pid "$vm_name")

    # Try graceful shutdown
    [[ -S "$VM_DIR/$vm_name.monitor" ]] && echo "system_powerdown" | socat - "UNIX-CONNECT:$VM_DIR/$vm_name.monitor" 2>/dev/null || true

    kill -TERM "$pid" 2>/dev/null || true

    local i=0
    while is_vm_running "$vm_name" && [[ $i -lt 10 ]]; do
        sleep 1
        ((i++))
    done

    is_vm_running "$vm_name" && kill -9 "$pid" 2>/dev/null
    rm -f "$VM_DIR/$vm_name.monitor" "$VM_DIR/$vm_name.serial" 2>/dev/null

    print_status "SUCCESS" "VM stopped"
}

delete_vm() {
    local vm_name=$1
    load_vm_config "$vm_name" || return 1

    is_vm_running "$vm_name" && { print_status "ERROR" "Stop VM first"; return 1; }

    print_status "WARN" "Delete VM '$vm_name'?"
    read -p "Type DELETE to confirm: " confirm

    [[ "$confirm" == "DELETE" ]] && {
        rm -f "$IMG_FILE" "$SEED_FILE" "$VM_DIR/$vm_name.conf" "$VM_DIR/$vm_name.monitor" "$VM_DIR/$vm_name.serial"
        print_status "SUCCESS" "VM deleted"
    } || print_status "INFO" "Cancelled"
}

show_vm_info() {
    local vm_name=$1
    load_vm_config "$vm_name" || return 1

    local status="Stopped" color="$C_RED"
    is_vm_running "$vm_name" && { status="Running"; color="$C_GREEN"; }

    echo
    printf "VM: %s [${color}%s${C_RESET}]\n" "$VM_NAME" "$status"
    echo "────────────────────────────────────────"
    printf "  OS: %s %s | Host: %s\n" "$OS_TYPE" "$OS_VERSION" "$HOSTNAME"
    printf "  User: %s | Pass: %s\n" "$USERNAME" "$PASSWORD"
    printf "  RAM: %sMB | CPUs: %s | Disk: %s\n" "$MEMORY" "$CPUS" "$DISK_SIZE"
    printf "  SSH: ssh -p %s %s@localhost\n" "$SSH_PORT" "$USERNAME"
    [[ -n "$PORT_FORWARDS" ]] && printf "  Ports: %s\n" "$PORT_FORWARDS"
    echo "────────────────────────────────────────"

    [[ -f "$IMG_FILE" ]] && qemu-img info "$IMG_FILE" 2>/dev/null | grep -E "virtual size|disk size" | sed 's/^/  /'
    echo
}

# ============================================
# Quick Create (New Feature)
# ============================================

quick_create_vm() {
    local os_choice=$1 vm_name=$2

    # Parse OS selection
    local os_data="${OS_OPTIONS[$os_choice]}"
    [[ -z "$os_data" ]] && { print_status "ERROR" "Unknown OS"; return 1; }

    IFS='|' read -r OS_TYPE OS_VERSION CODENAME IMG_URL DEFAULT_HOSTNAME DEFAULT_USERNAME DEFAULT_PASSWORD <<< "$os_data"

    VM_NAME="${vm_name:-$DEFAULT_HOSTNAME}"
    HOSTNAME="$VM_NAME"
    USERNAME="$DEFAULT_USERNAME"
    PASSWORD="$DEFAULT_PASSWORD"
    DISK_SIZE="$DEFAULT_DISK"
    MEMORY="$DEFAULT_MEMORY"
    CPUS="$DEFAULT_CPUS"
    SSH_PORT=$(find_available_port 2222)
    GUI_MODE=false
    PORT_FORWARDS=""
    IMG_FILE="$VM_DIR/$VM_NAME.qcow2"
    SEED_FILE="$VM_DIR/$VM_NAME-seed.iso"
    CREATED="$(date '+%Y-%m-%d %H:%M:%S')"

    print_status "INFO" "Quick creating: $VM_NAME ($OS_TYPE $OS_VERSION)"
    setup_vm_image || return 1
    save_vm_config

    print_status "SUCCESS" "VM '$VM_NAME' created!"
    echo "  Start: ./vm.sh start $VM_NAME"
    echo "  SSH: ssh -p $SSH_PORT $USERNAME@localhost"
}

# ============================================
# Create New VM (Interactive)
# ============================================

create_new_vm() {
    print_status "INFO" "Select OS:"
    echo

    local os_keys=() i=1
    while IFS= read -r os; do
        os_keys+=("$os")
        printf "  %2d) %s\n" "$i" "$os"
        ((i++))
    done < <(printf '%s\n' "${!OS_OPTIONS[@]}" | sort)
    echo

    local os_count=${#os_keys[@]}
    while true; do
        read -p "$(print_status "INPUT" "Choice (1-$os_count): ")" choice
        [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le "$os_count" ]] && break
        print_status "ERROR" "Invalid"
    done

    local os="${os_keys[$((choice-1))]}"
    IFS='|' read -r OS_TYPE OS_VERSION CODENAME IMG_URL DEFAULT_HOSTNAME DEFAULT_USERNAME DEFAULT_PASSWORD <<< "${OS_OPTIONS[$os]}"
    print_status "SUCCESS" "Selected: $os"
    echo

    # Get VM settings
    while true; do
        read -p "$(print_status "INPUT" "VM name [$DEFAULT_HOSTNAME]: ")" VM_NAME
        VM_NAME="${VM_NAME:-$DEFAULT_HOSTNAME}"
        validate_input "name" "$VM_NAME" && [[ ! -f "$VM_DIR/$VM_NAME.conf" ]] && break
        [[ -f "$VM_DIR/$VM_NAME.conf" ]] && print_status "ERROR" "VM exists"
    done

    read -p "$(print_status "INPUT" "Hostname [$VM_NAME]: ")" HOSTNAME
    HOSTNAME="${HOSTNAME:-$VM_NAME}"

    read -p "$(print_status "INPUT" "Username [$DEFAULT_USERNAME]: ")" USERNAME
    USERNAME="${USERNAME:-$DEFAULT_USERNAME}"

    read -s -p "$(print_status "INPUT" "Password [$DEFAULT_PASSWORD]: ")" PASSWORD
    echo
    PASSWORD="${PASSWORD:-$DEFAULT_PASSWORD}"

    read -p "$(print_status "INPUT" "Disk [$DEFAULT_DISK]: ")" DISK_SIZE
    DISK_SIZE="${DISK_SIZE:-$DEFAULT_DISK}"

    read -p "$(print_status "INPUT" "RAM MB [$DEFAULT_MEMORY]: ")" MEMORY
    MEMORY="${MEMORY:-$DEFAULT_MEMORY}"

    read -p "$(print_status "INPUT" "CPUs [$DEFAULT_CPUS]: ")" CPUS
    CPUS="${CPUS:-$DEFAULT_CPUS}"

    SSH_PORT=$(find_available_port 2222)
    read -p "$(print_status "INPUT" "SSH port [$SSH_PORT]: ")" input_port
    SSH_PORT="${input_port:-$SSH_PORT}"

    GUI_MODE=false
    read -p "$(print_status "INPUT" "Port forwards (8080:80,3000:3000): ")" PORT_FORWARDS

    IMG_FILE="$VM_DIR/$VM_NAME.qcow2"
    SEED_FILE="$VM_DIR/$VM_NAME-seed.iso"
    CREATED="$(date '+%Y-%m-%d %H:%M:%S')"

    echo
    print_status "INFO" "Summary: $VM_NAME | $OS_TYPE $OS_VERSION | ${MEMORY}MB | $CPUS CPU | $DISK_SIZE"
    read -p "$(print_status "INPUT" "Create? [Y/n]: ")" confirm
    [[ "$confirm" =~ ^[Nn]$ ]] && { print_status "INFO" "Cancelled"; return 1; }

    setup_vm_image || return 1
    save_vm_config

    print_status "SUCCESS" "VM '$VM_NAME' created!"
    print_status "INFO" "Start with option 2"
}

# ============================================
# Additional Functions
# ============================================

clone_vm() {
    local source=$1
    load_vm_config "$source" || return 1

    read -p "$(print_status "INPUT" "New name: ")" new_name
    [[ -z "$new_name" ]] && return 1
    [[ -f "$VM_DIR/$new_name.conf" ]] && { print_status "ERROR" "Exists"; return 1; }

    local src_img="$IMG_FILE"
    VM_NAME="$new_name"
    HOSTNAME="$new_name"
    IMG_FILE="$VM_DIR/$new_name.qcow2"
    SEED_FILE="$VM_DIR/$new_name-seed.iso"
    SSH_PORT=$(find_available_port "$SSH_PORT")
    CREATED="$(date '+%Y-%m-%d %H:%M:%S') (cloned)"

    print_status "INFO" "Cloning..."
    cp "$src_img" "$IMG_FILE" || return 1
    setup_vm_image
    save_vm_config
    print_status "SUCCESS" "Cloned to $new_name"
}

resize_disk() {
    local vm=$1
    load_vm_config "$vm" || return 1
    is_vm_running "$vm" && { print_status "ERROR" "Stop VM first"; return 1; }

    read -p "$(print_status "INPUT" "New size (e.g., 50G): ")" new_size
    validate_input "size" "$new_size" || return 1

    qemu-img resize "$IMG_FILE" "$new_size" 2>/dev/null && {
        DISK_SIZE="$new_size"
        save_vm_config
        print_status "SUCCESS" "Resized to $new_size"
    }
}

# Snapshot functions
create_snapshot() {
    local vm=$1
    load_vm_config "$vm" || return 1
    read -p "$(print_status "INPUT" "Snapshot name: ")" name
    qemu-img snapshot -c "$name" "$IMG_FILE" && print_status "SUCCESS" "Created"
}

list_snapshots() {
    local vm=$1
    load_vm_config "$vm" || return 1
    qemu-img snapshot -l "$IMG_FILE" 2>/dev/null || echo "No snapshots"
}

restore_snapshot() {
    local vm=$1
    load_vm_config "$vm" || return 1
    is_vm_running "$vm" && { print_status "ERROR" "Stop VM first"; return 1; }
    list_snapshots "$vm"
    read -p "$(print_status "INPUT" "Snapshot name: ")" name
    qemu-img snapshot -a "$name" "$IMG_FILE" && print_status "SUCCESS" "Restored"
}

delete_snapshot() {
    local vm=$1
    load_vm_config "$vm" || return 1
    list_snapshots "$vm"
    read -p "$(print_status "INPUT" "Snapshot name: ")" name
    qemu-img snapshot -d "$name" "$IMG_FILE" && print_status "SUCCESS" "Deleted"
}

show_system_info() {
    echo
    print_status "INFO" "System Info"
    echo "════════════════════════════════════════════"
    printf "  Host: %s | Kernel: %s\n" "$(hostname)" "$(uname -r)"
    printf "  CPUs: %s | RAM: %s | Free: %s\n" "$(nproc)" "$(free -h | awk '/Mem:/{print $2}')" "$(free -h | awk '/Mem:/{print $4}')"
    printf "  KVM: %s | QEMU: %s\n" "$KVM_AVAILABLE" "$(qemu-system-x86_64 --version 2>/dev/null | head -1 | awk '{print $4}')"
    [[ "$IDX_ENV" == "true" ]] && printf "  IDX Mode: Enabled | Cache: %s\n" "$CACHE_MODE"
    echo "════════════════════════════════════════════"
}

select_vm() {
    local prompt=$1
    shift
    local vms=("$@") count=${#vms[@]}

    [[ "$count" -eq 0 ]] && { print_status "ERROR" "No VMs"; return 1; }

    read -p "$(print_status "INPUT" "$prompt (1-$count): ")" num
    [[ "$num" =~ ^[0-9]+$ ]] && [[ "$num" -ge 1 ]] && [[ "$num" -le "$count" ]] && {
        echo "${vms[$((num-1))]}"
        return 0
    }
    return 1
}

# ============================================
# Command Line Interface
# ============================================

cli_usage() {
    cat <<EOF
Usage: $0 [command] [args]

Commands:
  list                    List all VMs
  create                  Interactive VM creation
  quick <os> [name]       Quick create (e.g., quick "Ubuntu 24.04 LTS (Noble)" myvm)
  start <vm>              Start VM in foreground
  startbg <vm>            Start VM in background
  stop <vm>               Stop VM
  delete <vm>             Delete VM
  info <vm>               Show VM info
  clone <vm>              Clone VM
  resize <vm>             Resize disk
  snapshot <vm>           Create snapshot
  snaplist <vm>           List snapshots
  restore <vm>            Restore snapshot
  system                  System info
  help                    Show this help

Examples:
  $0 quick "Debian 12 (Bookworm)" webserver
  $0 start webserver
  $0 stop webserver
EOF
}

# ============================================
# Main Menu
# ============================================

main_menu() {
    while true; do
        display_header

        local vms=()
        while IFS= read -r vm; do
            [[ -n "$vm" ]] && vms+=("$vm")
        done < <(get_vm_list)

        local count=${#vms[@]}

        if [[ $count -gt 0 ]]; then
            print_status "INFO" "VMs ($count):"
            for i in "${!vms[@]}"; do
                local st="○" col="$C_RED"
                is_vm_running "${vms[$i]}" && { st="●"; col="$C_GREEN"; }
                printf "  %2d) %-25s ${col}%s${C_RESET}\n" "$((i+1))" "${vms[$i]}" "$st"
            done
            echo
        fi

        echo "╔═══════════════════════════════════════╗"
        echo "║            Main Menu                  ║"
        echo "╠═══════════════════════════════════════╣"
        echo "║  1) Create VM    2) Start (fg)        ║"
        echo "║  3) Start (bg)   4) Stop VM           ║"
        echo "║  5) VM Info      6) Clone VM          ║"
        echo "║  7) Snapshots    8) Resize            ║"
        echo "║  9) Delete VM    s) System Info       ║"
        echo "║  0) Exit                              ║"
        echo "╚═══════════════════════════════════════╝"

        read -p "$(print_status "INPUT" "Choice: ")" choice

        case $choice in
            1) create_new_vm ;;
            2) [[ $count -gt 0 ]] && { vm=$(select_vm "Start" "${vms[@]}") && start_vm "$vm"; } ;;
            3) [[ $count -gt 0 ]] && { vm=$(select_vm "Start bg" "${vms[@]}") && start_vm_background "$vm"; } ;;
            4) [[ $count -gt 0 ]] && { vm=$(select_vm "Stop" "${vms[@]}") && stop_vm "$vm"; } ;;
            5) [[ $count -gt 0 ]] && { vm=$(select_vm "Info" "${vms[@]}") && show_vm_info "$vm"; } ;;
            6) [[ $count -gt 0 ]] && { vm=$(select_vm "Clone" "${vms[@]}") && clone_vm "$vm"; } ;;
            7)
                [[ $count -gt 0 ]] && {
                    vm=$(select_vm "Snapshot" "${vms[@]}") || continue
                    echo "  1) Create  2) List  3) Restore  4) Delete"
                    read -p "$(print_status "INPUT" "Action: ")" act
                    case $act in
                        1) create_snapshot "$vm" ;;
                        2) list_snapshots "$vm" ;;
                        3) restore_snapshot "$vm" ;;
                        4) delete_snapshot "$vm" ;;
                    esac
                } ;;
            8) [[ $count -gt 0 ]] && { vm=$(select_vm "Resize" "${vms[@]}") && resize_disk "$vm"; } ;;
            9) [[ $count -gt 0 ]] && { vm=$(select_vm "Delete" "${vms[@]}") && delete_vm "$vm"; } ;;
            s|S) show_system_info ;;
            0|q|Q) print_status "INFO" "Goodbye!"; exit 0 ;;
            *) print_status "ERROR" "Invalid" ;;
        esac

        echo
        read -p "Press Enter..."
    done
}

# ============================================
# OS Options (Cloud Images Only - Verified URLs)
# ============================================

declare -A OS_OPTIONS=(
    # Ubuntu
    ["Ubuntu 22.04 LTS (Jammy)"]="ubuntu|22.04|jammy|https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img|ubuntu22|ubuntu|ubuntu"
    ["Ubuntu 24.04 LTS (Noble)"]="ubuntu|24.04|noble|https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img|ubuntu24|ubuntu|ubuntu"
    ["Ubuntu 24.10 (Oracular)"]="ubuntu|24.10|oracular|https://cloud-images.ubuntu.com/oracular/current/oracular-server-cloudimg-amd64.img|ubuntu2410|ubuntu|ubuntu"

    # Debian
    ["Debian 11 (Bullseye)"]="debian|11|bullseye|https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-generic-amd64.qcow2|debian11|debian|debian"
    ["Debian 12 (Bookworm)"]="debian|12|bookworm|https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2|debian12|debian|debian"

    # Fedora
    ["Fedora 40"]="fedora|40|40|https://download.fedoraproject.org/pub/fedora/linux/releases/40/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-40-1.14.x86_64.qcow2|fedora40|fedora|fedora"
    ["Fedora 41"]="fedora|41|41|https://download.fedoraproject.org/pub/fedora/linux/releases/41/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-41-1.4.x86_64.qcow2|fedora41|fedora|fedora"

    # Enterprise
    ["CentOS Stream 9"]="centos|stream9|stream9|https://cloud.centos.org/centos/9-stream/x86_64/images/CentOS-Stream-GenericCloud-9-latest.x86_64.qcow2|centos9|cloud-user|centos"
    ["AlmaLinux 9"]="almalinux|9|9|https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-latest.x86_64.qcow2|alma9|almalinux|alma"
    ["Rocky Linux 9"]="rockylinux|9|9|https://download.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud.latest.x86_64.qcow2|rocky9|rocky|rocky"

    # Rolling/Arch
    ["Arch Linux"]="arch|rolling|latest|https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2|archlinux|arch|arch"

    # Lightweight
    ["Alpine Linux 3.20"]="alpine|3.20|v3.20|https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/cloud/nocloud_alpine-3.20.3-x86_64-bios-cloudinit-r0.qcow2|alpine|alpine|alpine"

    # openSUSE
    ["openSUSE Leap 15.6"]="opensuse|15.6|leap156|https://download.opensuse.org/distribution/leap/15.6/appliances/openSUSE-Leap-15.6-Minimal-VM.x86_64-Cloud.qcow2|opensuse|root|opensuse"

    # Security
    ["Kali Linux 2024.3"]="kali|2024.3|kali|https://kali.download/cloud-images/kali-2024.3/kali-linux-2024.3-cloud-genericcloud-amd64.qcow2|kali|kali|kali"

    # Cloud Provider
    ["Amazon Linux 2023"]="amazonlinux|2023|al2023|https://cdn.amazonlinux.com/al2023/os-images/2023.5.20241001.1/kvm/al2023-kvm-2023.5.20241001.1-kernel-6.1-x86_64.xfs.gpt.qcow2|amazonlinux|ec2-user|amazon"

    # Oracle
    ["Oracle Linux 9"]="oracle|9|ol9|https://yum.oracle.com/templates/OracleLinux/OL9/u5/x86_64/OL9U5_x86_64-kvm-b253.qcow2|oracle9|root|oracle"

    # Devuan (systemd-free)
    ["Devuan 5 (Daedalus)"]="devuan|5|daedalus|https://files.devuan.org/devuan_daedalus/virtual/devuan_daedalus_5.0.1_amd64_qemu.qcow2.xz|devuan|root|devuan"
)

# ============================================
# Entry Point
# ============================================

# Handle CLI arguments
if [[ $# -gt 0 ]]; then
    case "$1" in
        list) get_vm_list ;;
        create) display_header; check_dependencies; check_kvm; create_new_vm ;;
        quick) shift; quick_create_vm "$@" ;;
        start) shift; load_vm_config "$1" && start_vm "$1" ;;
        startbg) shift; load_vm_config "$1" && start_vm_background "$1" ;;
        stop) shift; stop_vm "$1" ;;
        delete) shift; delete_vm "$1" ;;
        info) shift; show_vm_info "$1" ;;
        clone) shift; clone_vm "$1" ;;
        resize) shift; resize_disk "$1" ;;
        snapshot) shift; create_snapshot "$1" ;;
        snaplist) shift; list_snapshots "$1" ;;
        restore) shift; restore_snapshot "$1" ;;
        system) show_system_info ;;
        help|--help|-h) cli_usage ;;
        *) cli_usage; exit 1 ;;
    esac
    exit 0
fi

# Interactive mode
display_header
print_status "INFO" "Checking system..."
check_dependencies
check_kvm
echo
main_menu
