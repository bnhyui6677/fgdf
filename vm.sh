#!/bin/bash
set -euo pipefail

# =============================
# Enhanced Multi-VM Manager v5.0 (Ultra Advanced)
# Optimized for: IDX GNU/Linux (Firebase Studio) & All Linux Systems
# Features: VM Edit, GPU Passthrough, Shared Folders, Monitoring, Backup/Restore,
#           Advanced Networking, USB Devices, Migration, No Limits
# =============================

VERSION="5.0"
KVM_AVAILABLE=true
QEMU_CMD=()

# Color codes
readonly C_RESET='\033[0m'
readonly C_RED='\033[1;31m'
readonly C_GREEN='\033[1;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_BLUE='\033[1;34m'
readonly C_MAGENTA='\033[1;35m'
readonly C_CYAN='\033[1;36m'
readonly C_WHITE='\033[1;37m'

# IDX/Firebase Studio detection
IDX_ENV=false
[[ -f /etc/os-release ]] && grep -q "IDX GNU/Linux" /etc/os-release 2>/dev/null && IDX_ENV=true

# System resource detection (no limits)
TOTAL_CPUS=$(nproc 2>/dev/null || echo 4)
TOTAL_MEM=$(awk '/MemTotal/{printf "%.0f", $2/1024}' /proc/meminfo 2>/dev/null || echo 4096)

# Optimized defaults based on environment
if [[ "$IDX_ENV" == "true" ]]; then
    DEFAULT_MEMORY=$((TOTAL_MEM / 2))
    DEFAULT_CPUS=$((TOTAL_CPUS > 1 ? TOTAL_CPUS - 1 : 1))
    DEFAULT_DISK="50G"
    CACHE_MODE="unsafe"
    TMPDIR="${TMPDIR:-/tmp}"
else
    DEFAULT_MEMORY=$((TOTAL_MEM / 2))
    DEFAULT_CPUS=$((TOTAL_CPUS > 1 ? TOTAL_CPUS - 1 : 1))
    DEFAULT_DISK="30G"
    CACHE_MODE="writeback"
fi

# Ensure reasonable minimums
[[ $DEFAULT_MEMORY -lt 1024 ]] && DEFAULT_MEMORY=1024
[[ $DEFAULT_CPUS -lt 1 ]] && DEFAULT_CPUS=1

# Initialize paths
VM_DIR="${VM_DIR:-$HOME/vms}"
BASE_IMG_DIR="$VM_DIR/.base-images"
DOWNLOAD_CACHE="$VM_DIR/.cache"
BACKUP_DIR="$VM_DIR/.backups"
SHARED_DIR="$VM_DIR/.shared"

# Ensure directories exist
mkdir -p "$VM_DIR" "$BASE_IMG_DIR" "$DOWNLOAD_CACHE" "$BACKUP_DIR" "$SHARED_DIR" 2>/dev/null || true

# ============================================
# Utility Functions
# ============================================

print_status() {
    local type="$1"
    local msg="$2"
    case "$type" in
        INFO)    printf "${C_BLUE}[INFO]${C_RESET} %s\n" "$msg" ;;
        WARN)    printf "${C_YELLOW}[WARN]${C_RESET} %s\n" "$msg" ;;
        ERROR)   printf "${C_RED}[ERROR]${C_RESET} %s\n" "$msg" ;;
        SUCCESS) printf "${C_GREEN}[SUCCESS]${C_RESET} %s\n" "$msg" ;;
        INPUT)   printf "${C_CYAN}[INPUT]${C_RESET} %s" "$msg" ;;
        DEBUG)   printf "${C_MAGENTA}[DEBUG]${C_RESET} %s\n" "$msg" ;;
        *)       printf "[%s] %s\n" "$type" "$msg" ;;
    esac
}

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
    printf "         CPUs: %s | RAM: %sMB | Disk: %s\n" "$DEFAULT_CPUS" "$DEFAULT_MEMORY" "$DEFAULT_DISK"
    echo "========================================================================"
    echo
}

validate_input() {
    local type="$1"
    local value="$2"
    case "$type" in
        number)
            [[ "$value" =~ ^[0-9]+$ ]] && [[ "$value" -gt 0 ]] && return 0
            print_status "ERROR" "Must be a positive number"
            return 1
            ;;
        size)
            [[ "$value" =~ ^[0-9]+[GgMm]$ ]] && return 0
            print_status "ERROR" "Must be size with unit (e.g., 100G, 512M)"
            return 1
            ;;
        port)
            [[ "$value" =~ ^[0-9]+$ ]] && [[ "$value" -ge 1024 ]] && [[ "$value" -le 65535 ]] && return 0
            print_status "ERROR" "Must be valid port (1024-65535)"
            return 1
            ;;
        name)
            [[ "$value" =~ ^[a-zA-Z0-9_-]+$ ]] && [[ ${#value} -le 64 ]] && return 0
            print_status "ERROR" "Invalid name (use letters, numbers, hyphens, underscores)"
            return 1
            ;;
        username)
            [[ "$value" =~ ^[a-z][a-z0-9_-]*$ ]] && [[ ${#value} -le 32 ]] && return 0
            print_status "ERROR" "Invalid username"
            return 1
            ;;
        password)
            [[ ${#value} -ge 1 ]] && return 0
            print_status "ERROR" "Password cannot be empty"
            return 1
            ;;
        path)
            [[ -e "$value" ]] && return 0
            print_status "ERROR" "Path does not exist"
            return 1
            ;;
    esac
    return 1
}

check_kvm() {
    if [[ -e /dev/kvm ]] && [[ -r /dev/kvm ]] && [[ -w /dev/kvm ]]; then
        KVM_AVAILABLE=true
        print_status "SUCCESS" "KVM acceleration available"
    else
        KVM_AVAILABLE=false
        print_status "WARN" "KVM not available - VMs will run in emulation mode (slower)"
    fi
}

check_dependencies() {
    local missing=()
    local deps=(qemu-system-x86_64 wget qemu-img)

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing+=("$dep")
        fi
    done

    if [[ ${#missing[@]} -ne 0 ]]; then
        print_status "ERROR" "Missing dependencies: ${missing[*]}"
        echo "Install with: sudo apt install -y qemu-system-x86 qemu-utils wget"
        exit 1
    fi
    print_status "SUCCESS" "All dependencies found"
    [[ "$IDX_ENV" == "true" ]] && print_status "INFO" "IDX optimizations enabled"
}

is_port_available() {
    local port="$1"
    ! ss -tuln 2>/dev/null | grep -q ":${port} " && \
    ! grep -q ":$(printf '%04X' "$port") " /proc/net/tcp /proc/net/tcp6 2>/dev/null
}

find_available_port() {
    local port="${1:-2222}"
    local max_port=65535
    while ! is_port_available "$port" && [[ "$port" -lt "$max_port" ]]; do
        ((port++))
    done
    echo "$port"
}

get_vm_list() {
    local vms=()
    if [[ -d "$VM_DIR" ]]; then
        for f in "$VM_DIR"/*.conf; do
            [[ -f "$f" ]] && vms+=("$(basename "${f%.conf}")")
        done
    fi
    printf '%s\n' "${vms[@]}" 2>/dev/null | sort
}

load_vm_config() {
    local config_file="$VM_DIR/$1.conf"
    if [[ ! -f "$config_file" ]]; then
        print_status "ERROR" "VM '$1' not found"
        return 1
    fi

    # Reset variables
    unset VM_NAME OS_TYPE OS_VERSION CODENAME IMG_URL HOSTNAME USERNAME PASSWORD
    unset DISK_SIZE MEMORY CPUS SSH_PORT GUI_MODE PORT_FORWARDS IMG_FILE SEED_FILE CREATED
    unset SHARED_FOLDERS GPU_PASSTHROUGH USB_DEVICES NETWORK_MODE BRIDGE_NAME CUSTOM_ARGS
    unset VNCSOCKET VNC_PORT SPICE_PORT AUDIO_DEVICE TPM_ENABLED UEFI_ENABLED SECURE_BOOT

    source "$config_file"
    return 0
}

save_vm_config() {
    cat > "$VM_DIR/$VM_NAME.conf" << EOF
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
GUI_MODE="${GUI_MODE:-false}"
PORT_FORWARDS="${PORT_FORWARDS:-}"
IMG_FILE="$IMG_FILE"
SEED_FILE="$SEED_FILE"
CREATED="$CREATED"
SHARED_FOLDERS="${SHARED_FOLDERS:-}"
GPU_PASSTHROUGH="${GPU_PASSTHROUGH:-}"
USB_DEVICES="${USB_DEVICES:-}"
NETWORK_MODE="${NETWORK_MODE:-user}"
BRIDGE_NAME="${BRIDGE_NAME:-}"
CUSTOM_ARGS="${CUSTOM_ARGS:-}"
VNC_PORT="${VNC_PORT:-}"
SPICE_PORT="${SPICE_PORT:-}"
AUDIO_DEVICE="${AUDIO_DEVICE:-}"
TPM_ENABLED="${TPM_ENABLED:-false}"
UEFI_ENABLED="${UEFI_ENABLED:-false}"
SECURE_BOOT="${SECURE_BOOT:-false}"
EOF
    chmod 600 "$VM_DIR/$VM_NAME.conf"
}

cleanup() {
    rm -f user-data meta-data network-config 2>/dev/null || true
}
trap cleanup EXIT

# ============================================
# Download Functions
# ============================================

decompress_if_needed() {
    local file="$1"
    local output="$2"

    case "$file" in
        *.xz)
            print_status "INFO" "Decompressing XZ archive..."
            if command -v xz &>/dev/null; then
                xz -dkf "$file" 2>/dev/null && mv "${file%.xz}" "$output"
            elif command -v unxz &>/dev/null; then
                unxz -k "$file" 2>/dev/null && mv "${file%.xz}" "$output"
            else
                print_status "ERROR" "xz decompression tool not found"
                return 1
            fi
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
        *.tar.xz)
            print_status "INFO" "Extracting TAR.XZ archive..."
            tar -xJf "$file" -C "$(dirname "$output")" && rm -f "$file"
            local extracted
            extracted=$(find "$(dirname "$output")" -name "*.qcow2" -o -name "*.img" 2>/dev/null | head -1)
            [[ -n "$extracted" ]] && mv "$extracted" "$output"
            ;;
        *)
            [[ "$file" != "$output" ]] && mv "$file" "$output"
            ;;
    esac
    return 0
}

download_image() {
    local url="$1"
    local output="$2"
    local tmp_file="${output}.tmp"
    local filename
    filename=$(basename "$url")

    print_status "INFO" "Downloading: $filename"
    print_status "INFO" "URL: $url"

    # Determine extension for temp file
    case "$url" in
        *.xz|*.gz|*.bz2|*.tar.xz)
            tmp_file="${output}.${url##*.}"
            ;;
    esac

    # Download with progress
    if command -v curl &>/dev/null; then
        if ! curl -fL --progress-bar --retry 3 --retry-delay 5 -C - -o "$tmp_file" "$url"; then
            rm -f "$tmp_file"
            print_status "ERROR" "Download failed"
            return 1
        fi
    else
        if ! wget --progress=bar:force:noscroll --timeout=60 --tries=3 -c -O "$tmp_file" "$url" 2>&1; then
            rm -f "$tmp_file"
            print_status "ERROR" "Download failed"
            return 1
        fi
    fi

    # Decompress if needed
    decompress_if_needed "$tmp_file" "$output" || return 1
    print_status "SUCCESS" "Download completed"
    return 0
}

detect_image_format() {
    local img="$1"
    local format
    format=$(qemu-img info "$img" 2>/dev/null | awk '/file format:/{print $3}')
    echo "${format:-qcow2}"
}

# ============================================
# Password Hash Generation
# ============================================

generate_password_hash() {
    local password="$1"
    local hash=""

    # Try openssl first (most reliable)
    if command -v openssl &>/dev/null; then
        local salt
        salt=$(openssl rand -base64 12 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c 16)
        hash=$(openssl passwd -6 -salt "$salt" "$password" 2>/dev/null)
        if [[ -n "$hash" ]] && [[ "$hash" == "\$6\$"* ]]; then
            echo "$hash"
            return 0
        fi
    fi

    # Try mkpasswd
    if command -v mkpasswd &>/dev/null; then
        hash=$(mkpasswd -m sha-512 "$password" 2>/dev/null)
        if [[ -n "$hash" ]] && [[ "$hash" == "\$6\$"* ]]; then
            echo "$hash"
            return 0
        fi
    fi

    # Try python3
    if command -v python3 &>/dev/null; then
        hash=$(python3 -c "
import crypt
import secrets
salt = crypt.mksalt(crypt.METHOD_SHA512)
print(crypt.crypt('$password', salt))
" 2>/dev/null)
        if [[ -n "$hash" ]] && [[ "$hash" == "\$6\$"* ]]; then
            echo "$hash"
            return 0
        fi
    fi

    # Return empty if all methods fail
    echo ""
}

create_cloud_init_iso() {
    local user_data="$1"
    local meta_data="$2"
    local output="$3"

    if command -v cloud-localds &>/dev/null; then
        cloud-localds "$output" "$user_data" "$meta_data" 2>/dev/null && return 0
    fi

    local tools=(genisoimage mkisofs xorriso)
    for tool in "${tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            case "$tool" in
                genisoimage|mkisofs)
                    "$tool" -output "$output" -volid cidata -joliet -rock "$user_data" "$meta_data" 2>/dev/null && return 0
                    ;;
                xorriso)
                    xorriso -as mkisofs -o "$output" -V cidata -J -r "$user_data" "$meta_data" 2>/dev/null && return 0
                    ;;
            esac
        fi
    done

    print_status "ERROR" "No ISO creation tool available (install genisoimage)"
    return 1
}

# ============================================
# VM Image Setup
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

    local img_format
    img_format=$(detect_image_format "$base_img")

    # Remove old disk if exists
    rm -f "$IMG_FILE" 2>/dev/null

    # Create overlay disk (faster) or full copy
    if qemu-img create -f qcow2 -F "$img_format" -b "$base_img" "$IMG_FILE" "$DISK_SIZE" 2>/dev/null; then
        print_status "SUCCESS" "Created overlay disk"
    else
        print_status "INFO" "Creating full copy (this may take a while)..."
        cp "$base_img" "$IMG_FILE"
        if [[ "$img_format" != "qcow2" ]]; then
            qemu-img convert -f "$img_format" -O qcow2 "$IMG_FILE" "${IMG_FILE}.tmp" 2>/dev/null
            mv "${IMG_FILE}.tmp" "$IMG_FILE"
        fi
        qemu-img resize "$IMG_FILE" "$DISK_SIZE" 2>/dev/null || true
    fi

    # Generate password hash
    local password_hash
    password_hash=$(generate_password_hash "$PASSWORD")

    # Create cloud-init user-data
    cat > user-data << EOF
#cloud-config
hostname: $HOSTNAME
manage_etc_hosts: true
fqdn: ${HOSTNAME}.local

users:
  - name: $USERNAME
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: [sudo, adm, wheel, users]
    shell: /bin/bash
    lock_passwd: false
EOF

    # Add password hash if generated successfully
    if [[ -n "$password_hash" ]]; then
        cat >> user-data << EOF
    hashed_passwd: '$password_hash'
EOF
    fi

    cat >> user-data << EOF

chpasswd:
  expire: false
  list:
    - root:$PASSWORD
    - $USERNAME:$PASSWORD

ssh_pwauth: true
disable_root: false

write_files:
  - path: /etc/ssh/sshd_config.d/99-custom.conf
    content: |
      PasswordAuthentication yes
      PermitRootLogin yes
      UsePAM yes
      ChallengeResponseAuthentication no

  - path: /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
    content: |
      network: {config: disabled}

runcmd:
  - echo "$USERNAME:$PASSWORD" | chpasswd
  - echo "root:$PASSWORD" | chpasswd
  - sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
  - sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
  - systemctl restart sshd || systemctl restart ssh || service ssh restart || true
  - systemctl disable cloud-init || true

final_message: "System ready! User: $USERNAME | Password: $PASSWORD"
EOF

    # Create meta-data
    cat > meta-data << EOF
instance-id: iid-${VM_NAME}-$(date +%s)
local-hostname: $HOSTNAME
EOF

    # Create cloud-init ISO
    if ! create_cloud_init_iso "user-data" "meta-data" "$SEED_FILE"; then
        return 1
    fi

    cleanup
    print_status "SUCCESS" "VM image ready"
    return 0
}

# ============================================
# QEMU Command Builders
# ============================================

build_qemu_base() {
    local name="$1"
    QEMU_CMD=(qemu-system-x86_64)

    # Machine type with KVM acceleration
    if $KVM_AVAILABLE; then
        QEMU_CMD+=(-machine type=q35,accel=kvm)
        QEMU_CMD+=(-enable-kvm)
        QEMU_CMD+=(-cpu host)
    else
        QEMU_CMD+=(-machine type=q35,accel=tcg)
        QEMU_CMD+=(-cpu qemu64)
    fi

    QEMU_CMD+=(-name "$name")
    QEMU_CMD+=(-m "$MEMORY")
    QEMU_CMD+=(-smp "$CPUS",cores="$CPUS",threads=1)

    # Main disk with optimized caching
    QEMU_CMD+=(-drive "file=$IMG_FILE,format=qcow2,if=virtio,cache=$CACHE_MODE,discard=unmap")

    # Cloud-init seed ISO
    if [[ -f "$SEED_FILE" ]]; then
        QEMU_CMD+=(-drive "file=$SEED_FILE,format=raw,if=virtio,readonly=on")
    fi

    # Boot order
    QEMU_CMD+=(-boot order=c)

    # Network configuration
    case "${NETWORK_MODE:-user}" in
        user)
            local netdev="user,id=net0,hostfwd=tcp::${SSH_PORT}-:22"
            if [[ -n "${PORT_FORWARDS:-}" ]]; then
                IFS=',' read -ra fwds <<< "$PORT_FORWARDS"
                for fwd in "${fwds[@]}"; do
                    if [[ "$fwd" =~ ^[0-9]+:[0-9]+$ ]]; then
                        netdev+=",hostfwd=tcp::${fwd%:*}-:${fwd#*:}"
                    fi
                done
            fi
            QEMU_CMD+=(-device virtio-net-pci,netdev=net0)
            QEMU_CMD+=(-netdev "$netdev")
            ;;
        bridge)
            if [[ -n "${BRIDGE_NAME:-}" ]]; then
                QEMU_CMD+=(-netdev "bridge,id=net0,br=${BRIDGE_NAME}")
                QEMU_CMD+=(-device virtio-net-pci,netdev=net0)
            else
                print_status "WARN" "Bridge name not set, falling back to user mode"
                QEMU_CMD+=(-netdev "user,id=net0,hostfwd=tcp::${SSH_PORT}-:22")
                QEMU_CMD+=(-device virtio-net-pci,netdev=net0)
            fi
            ;;
        tap)
            QEMU_CMD+=(-netdev "tap,id=net0,ifname=tap-${name},script=no,downscript=no")
            QEMU_CMD+=(-device virtio-net-pci,netdev=net0)
            ;;
    esac

    # Performance devices
    QEMU_CMD+=(-device virtio-balloon-pci)
    QEMU_CMD+=(-object rng-random,filename=/dev/urandom,id=rng0)
    QEMU_CMD+=(-device virtio-rng-pci,rng=rng0)

    # Shared folders (virtfs/9p)
    if [[ -n "${SHARED_FOLDERS:-}" ]]; then
        IFS=',' read -ra folders <<< "$SHARED_FOLDERS"
        for folder in "${folders[@]}"; do
            if [[ "$folder" =~ ^(.+):(.+)$ ]]; then
                local host_path="${BASH_REMATCH[1]}"
                local mount_tag="${BASH_REMATCH[2]}"
                if [[ -d "$host_path" ]]; then
                    QEMU_CMD+=(-virtfs "local,path=$host_path,mount_tag=$mount_tag,security_model=passthrough,id=fs-$mount_tag")
                fi
            fi
        done
    fi

    # GPU Passthrough
    if [[ -n "${GPU_PASSTHROUGH:-}" ]]; then
        IFS=',' read -ra gpus <<< "$GPU_PASSTHROUGH"
        for gpu in "${gpus[@]}"; do
            if [[ -e "/dev/vfio/$gpu" ]] || [[ "$gpu" =~ ^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-9a-f]$ ]]; then
                QEMU_CMD+=(-device "vfio-pci,host=$gpu")
            fi
        done
    fi

    # USB Devices
    if [[ -n "${USB_DEVICES:-}" ]]; then
        IFS=',' read -ra usbs <<< "$USB_DEVICES"
        for usb in "${usbs[@]}"; do
            if [[ "$usb" =~ ^([0-9a-f]{4}):([0-9a-f]{4})$ ]]; then
                QEMU_CMD+=(-device "usb-host,vendorid=0x${BASH_REMATCH[1]},productid=0x${BASH_REMATCH[2]}")
            fi
        done
    fi

    # TPM support
    if [[ "${TPM_ENABLED:-false}" == "true" ]]; then
        QEMU_CMD+=(-chardev "socket,id=chrtpm,path=/tmp/swtpm-$name")
        QEMU_CMD+=(-tpmdev "emulator,id=tpm0,chardev=chrtpm")
        QEMU_CMD+=(-device "tpm-tis,tpmdev=tpm0")
    fi

    # Audio device
    if [[ -n "${AUDIO_DEVICE:-}" ]]; then
        QEMU_CMD+=(-audiodev "pa,id=audio0")
        QEMU_CMD+=(-device "${AUDIO_DEVICE},audiodev=audio0")
    fi

    # Custom arguments
    if [[ -n "${CUSTOM_ARGS:-}" ]]; then
        IFS=' ' read -ra args <<< "$CUSTOM_ARGS"
        QEMU_CMD+=("${args[@]}")
    fi
}

build_qemu_foreground() {
    build_qemu_base "$1"

    if [[ "${GUI_MODE:-false}" == "true" ]]; then
        QEMU_CMD+=(-vga virtio)
        QEMU_CMD+=(-display gtk,gl=on)
    else
        QEMU_CMD+=(-display none)
        QEMU_CMD+=(-serial telnet::4321,server,nowait)
        QEMU_CMD+=(-daemonize)
        QEMU_CMD+=(-monitor "unix:$VM_DIR/$1.monitor,server,nowait")
        QEMU_CMD+=(-pidfile "$VM_DIR/$1.pid")
    fi
}

build_qemu_background() {
    build_qemu_base "$1"

    if [[ -n "${VNC_PORT:-}" ]]; then
        QEMU_CMD+=(-vnc ":${VNC_PORT}")
        QEMU_CMD+=(-vga virtio)
    elif [[ -n "${SPICE_PORT:-}" ]]; then
        QEMU_CMD+=(-spice "port=${SPICE_PORT},disable-ticketing=on")
        QEMU_CMD+=(-vga qxl)
        QEMU_CMD+=(-device virtio-serial)
        QEMU_CMD+=(-chardev "spicevmc,id=vdagent,name=vdagent")
        QEMU_CMD+=(-device "virtserialport,chardev=vdagent,name=com.redhat.spice.0")
    else
        QEMU_CMD+=(-display none)
    fi

    QEMU_CMD+=(-daemonize)
    QEMU_CMD+=(-monitor "unix:$VM_DIR/$1.monitor,server,nowait")
    QEMU_CMD+=(-serial "unix:$VM_DIR/$1.serial,server,nowait")
    QEMU_CMD+=(-pidfile "$VM_DIR/$1.pid")
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
    local vm_name="$1"

    if ! load_vm_config "$vm_name"; then
        return 1
    fi

    if is_vm_running "$vm_name"; then
        print_status "WARN" "VM '$vm_name' is already running"
        return 1
    fi

    if [[ ! -f "$IMG_FILE" ]]; then
        print_status "ERROR" "Image file not found: $IMG_FILE"
        return 1
    fi

    # Find available port if current is in use
    if ! is_port_available "$SSH_PORT"; then
        SSH_PORT=$(find_available_port "$SSH_PORT")
        save_vm_config
        print_status "INFO" "SSH port changed to $SSH_PORT"
    fi

    echo
    print_status "INFO" "Starting VM: $vm_name"
    echo "════════════════════════════════════════════════════════"
    echo "  OS:       $OS_TYPE $OS_VERSION"
    echo "  SSH:      ssh -p $SSH_PORT $USERNAME@localhost"
    echo "  User:     $USERNAME"
    echo "  Password: $PASSWORD"
    echo "  RAM:      ${MEMORY}MB | CPUs: $CPUS"
    [[ -n "${VNC_PORT:-}" ]] && echo "  VNC:      localhost:${VNC_PORT}"
    [[ -n "${SPICE_PORT:-}" ]] && echo "  SPICE:    localhost:${SPICE_PORT}"
    echo "════════════════════════════════════════════════════════"
    print_status "INFO" "Wait 30-60 seconds for cloud-init to complete"
    [[ "${GUI_MODE:-false}" != "true" ]] && print_status "INFO" "Serial console: telnet localhost 4321"
    echo

    build_qemu_foreground "$vm_name"
    if "${QEMU_CMD[@]}" 2>/dev/null; then
        sleep 2
        if is_vm_running "$vm_name"; then
            print_status "SUCCESS" "VM started successfully"
            print_status "INFO" "Connect via: ssh -p $SSH_PORT $USERNAME@localhost"
            [[ "${GUI_MODE:-false}" != "true" ]] && print_status "INFO" "Or use serial console: telnet localhost 4321"
        else
            print_status "ERROR" "Failed to start VM"
            return 1
        fi
    else
        print_status "ERROR" "QEMU command failed"
        return 1
    fi
}

start_vm_background() {
    local vm_name="$1"

    if ! load_vm_config "$vm_name"; then
        return 1
    fi

    if is_vm_running "$vm_name"; then
        print_status "WARN" "VM '$vm_name' is already running"
        return 1
    fi

    if [[ ! -f "$IMG_FILE" ]]; then
        print_status "ERROR" "Image file not found"
        return 1
    fi

    if ! is_port_available "$SSH_PORT"; then
        SSH_PORT=$(find_available_port "$SSH_PORT")
        save_vm_config
    fi

    print_status "INFO" "Starting $vm_name in background..."
    build_qemu_background "$vm_name"

    if "${QEMU_CMD[@]}" 2>/dev/null; then
        sleep 2
        if is_vm_running "$vm_name"; then
            print_status "SUCCESS" "VM started successfully"
            echo "  SSH: ssh -p $SSH_PORT $USERNAME@localhost"
            echo "  User: $USERNAME | Password: $PASSWORD"
            [[ -n "${VNC_PORT:-}" ]] && echo "  VNC: localhost:${VNC_PORT}"
            [[ -n "${SPICE_PORT:-}" ]] && echo "  SPICE: localhost:${SPICE_PORT}"
            print_status "INFO" "Wait 30-60 seconds for cloud-init"
        else
            print_status "ERROR" "Failed to start VM"
            return 1
        fi
    else
        print_status "ERROR" "QEMU command failed"
        return 1
    fi
}

stop_vm() {
    local vm_name="$1"

    if ! load_vm_config "$vm_name"; then
        return 1
    fi

    if ! is_vm_running "$vm_name"; then
        print_status "INFO" "VM '$vm_name' is not running"
        return 0
    fi

    local pid
    pid=$(get_vm_pid "$vm_name")

    # Try graceful shutdown via monitor
    if [[ -S "$VM_DIR/$vm_name.monitor" ]]; then
        echo "system_powerdown" | socat - "UNIX-CONNECT:$VM_DIR/$vm_name.monitor" 2>/dev/null || true
    fi

    # Send SIGTERM
    kill -TERM "$pid" 2>/dev/null || true

    # Wait for graceful shutdown
    local i=0
    while is_vm_running "$vm_name" && [[ $i -lt 15 ]]; do
        sleep 1
        ((i++))
        printf "."
    done
    echo

    # Force kill if still running
    if is_vm_running "$vm_name"; then
        kill -9 "$pid" 2>/dev/null || true
    fi

    # Cleanup socket files
    rm -f "$VM_DIR/$vm_name.monitor" "$VM_DIR/$vm_name.serial" "$VM_DIR/$vm_name.pid" 2>/dev/null

    print_status "SUCCESS" "VM '$vm_name' stopped"
}

delete_vm() {
    local vm_name="$1"

    if ! load_vm_config "$vm_name"; then
        return 1
    fi

    if is_vm_running "$vm_name"; then
        print_status "ERROR" "Please stop the VM first"
        return 1
    fi

    print_status "WARN" "This will permanently delete VM '$vm_name'"
    read -p "Type 'DELETE' to confirm: " confirm

    if [[ "$confirm" == "DELETE" ]]; then
        rm -f "$IMG_FILE" "$SEED_FILE" "$VM_DIR/$vm_name.conf"
        rm -f "$VM_DIR/$vm_name.monitor" "$VM_DIR/$vm_name.serial" "$VM_DIR/$vm_name.pid"
        print_status "SUCCESS" "VM '$vm_name' deleted"
    else
        print_status "INFO" "Deletion cancelled"
    fi
}

show_vm_info() {
    local vm_name="$1"

    if ! load_vm_config "$vm_name"; then
        return 1
    fi

    local status="Stopped"
    local color="$C_RED"
    if is_vm_running "$vm_name"; then
        status="Running"
        color="$C_GREEN"
    fi

    echo
    printf "VM: ${C_WHITE}%s${C_RESET} [${color}%s${C_RESET}]\n" "$VM_NAME" "$status"
    echo "────────────────────────────────────────────────────"
    printf "  OS:       %s %s (%s)\n" "$OS_TYPE" "$OS_VERSION" "$CODENAME"
    printf "  Hostname: %s\n" "$HOSTNAME"
    printf "  User:     %s\n" "$USERNAME"
    printf "  Password: %s\n" "$PASSWORD"
    printf "  RAM:      %sMB\n" "$MEMORY"
    printf "  CPUs:     %s\n" "$CPUS"
    printf "  Disk:     %s\n" "$DISK_SIZE"
    printf "  SSH:      ssh -p %s %s@localhost\n" "$SSH_PORT" "$USERNAME"
    [[ -n "${PORT_FORWARDS:-}" ]] && printf "  Ports:    %s\n" "$PORT_FORWARDS"
    [[ -n "${VNC_PORT:-}" ]] && printf "  VNC:      localhost:%s\n" "$VNC_PORT"
    [[ -n "${SPICE_PORT:-}" ]] && printf "  SPICE:    localhost:%s\n" "$SPICE_PORT"
    [[ -n "${SHARED_FOLDERS:-}" ]] && printf "  Shared:   %s\n" "$SHARED_FOLDERS"
    [[ -n "${GPU_PASSTHROUGH:-}" ]] && printf "  GPU:      %s\n" "$GPU_PASSTHROUGH"
    [[ -n "${USB_DEVICES:-}" ]] && printf "  USB:      %s\n" "$USB_DEVICES"
    [[ "${TPM_ENABLED:-false}" == "true" ]] && printf "  TPM:      Enabled\n"
    [[ "${UEFI_ENABLED:-false}" == "true" ]] && printf "  UEFI:     Enabled\n"
    printf "  Network:  %s\n" "${NETWORK_MODE:-user}"
    [[ -n "${BRIDGE_NAME:-}" ]] && printf "  Bridge:   %s\n" "$BRIDGE_NAME"
    [[ -n "${CUSTOM_ARGS:-}" ]] && printf "  Custom:   %s\n" "$CUSTOM_ARGS"
    printf "  Created:  %s\n" "$CREATED"
    echo "────────────────────────────────────────────────────"

    if [[ -f "$IMG_FILE" ]]; then
        echo "  Disk Info:"
        qemu-img info "$IMG_FILE" 2>/dev/null | grep -E "virtual size|disk size" | sed 's/^/    /'
    fi

    if is_vm_running "$vm_name"; then
        local pid
        pid=$(get_vm_pid "$vm_name")
        echo "  Process:"
        printf "    PID: %s\n" "$pid"
        if [[ -f "/proc/$pid/status" ]]; then
            local mem_kb
            mem_kb=$(grep VmRSS /proc/$pid/status | awk '{print $2}')
            printf "    Memory: %d MB\n" "$((mem_kb / 1024))"
        fi
    fi
    echo
}

# ============================================
# VM Edit Function (NEW)
# ============================================

edit_vm() {
    local vm_name="$1"

    if ! load_vm_config "$vm_name"; then
        return 1
    fi

    if is_vm_running "$vm_name"; then
        print_status "WARN" "VM is running. Some changes require stopping the VM."
    fi

    while true; do
        echo
        print_status "INFO" "Edit VM: $vm_name"
        echo "════════════════════════════════════════════════════════"
        echo "  1) Memory (Current: ${MEMORY}MB)"
        echo "  2) CPUs (Current: ${CPUS})"
        echo "  3) Disk Size (Current: ${DISK_SIZE})"
        echo "  4) SSH Port (Current: ${SSH_PORT})"
        echo "  5) Port Forwards (Current: ${PORT_FORWARDS:-none})"
        echo "  6) Shared Folders (Current: ${SHARED_FOLDERS:-none})"
        echo "  7) Network Mode (Current: ${NETWORK_MODE:-user})"
        echo "  8) GPU Passthrough (Current: ${GPU_PASSTHROUGH:-none})"
        echo "  9) USB Devices (Current: ${USB_DEVICES:-none})"
        echo " 10) VNC Port (Current: ${VNC_PORT:-disabled})"
        echo " 11) SPICE Port (Current: ${SPICE_PORT:-disabled})"
        echo " 12) TPM Support (Current: ${TPM_ENABLED:-false})"
        echo " 13) Custom Arguments (Current: ${CUSTOM_ARGS:-none})"
        echo " 14) Username (Current: ${USERNAME})"
        echo " 15) Password (Current: ${PASSWORD})"
        echo " 16) Hostname (Current: ${HOSTNAME})"
        echo "  0) Save and Exit"
        echo "════════════════════════════════════════════════════════"

        read -p "$(print_status "INPUT" "Select option: ")" choice

        case "$choice" in
            1)
                read -p "$(print_status "INPUT" "New memory (MB) [$MEMORY]: ")" new_mem
                if [[ -n "$new_mem" ]] && validate_input "number" "$new_mem"; then
                    MEMORY="$new_mem"
                    print_status "SUCCESS" "Memory updated"
                fi
                ;;
            2)
                read -p "$(print_status "INPUT" "New CPU count [$CPUS]: ")" new_cpu
                if [[ -n "$new_cpu" ]] && validate_input "number" "$new_cpu"; then
                    CPUS="$new_cpu"
                    print_status "SUCCESS" "CPUs updated"
                fi
                ;;
            3)
                if is_vm_running "$vm_name"; then
                    print_status "ERROR" "Stop VM before resizing disk"
                else
                    read -p "$(print_status "INPUT" "New disk size (e.g., 50G) [$DISK_SIZE]: ")" new_size
                    if [[ -n "$new_size" ]] && validate_input "size" "$new_size"; then
                        if qemu-img resize "$IMG_FILE" "$new_size" 2>/dev/null; then
                            DISK_SIZE="$new_size"
                            print_status "SUCCESS" "Disk resized (run resize2fs in VM)"
                        else
                            print_status "ERROR" "Failed to resize disk"
                        fi
                    fi
                fi
                ;;
            4)
                read -p "$(print_status "INPUT" "New SSH port [$SSH_PORT]: ")" new_port
                if [[ -n "$new_port" ]] && validate_input "port" "$new_port"; then
                    SSH_PORT="$new_port"
                    print_status "SUCCESS" "SSH port updated"
                fi
                ;;
            5)
                read -p "$(print_status "INPUT" "Port forwards (host:guest,host:guest) [$PORT_FORWARDS]: ")" new_fwd
                PORT_FORWARDS="$new_fwd"
                print_status "SUCCESS" "Port forwards updated"
                ;;
            6)
                read -p "$(print_status "INPUT" "Shared folders (host_path:mount_tag) [$SHARED_FOLDERS]: ")" new_shared
                SHARED_FOLDERS="$new_shared"
                print_status "SUCCESS" "Shared folders updated"
                print_status "INFO" "Mount in VM: mount -t 9p -o trans=virtio mount_tag /mount/point"
                ;;
            7)
                echo "Network modes: user, bridge, tap"
                read -p "$(print_status "INPUT" "Network mode [${NETWORK_MODE:-user}]: ")" new_net
                if [[ -n "$new_net" ]]; then
                    NETWORK_MODE="$new_net"
                    if [[ "$new_net" == "bridge" ]]; then
                        read -p "$(print_status "INPUT" "Bridge name: ")" bridge
                        BRIDGE_NAME="$bridge"
                    fi
                    print_status "SUCCESS" "Network mode updated"
                fi
                ;;
            8)
                print_status "INFO" "Enter PCI address (e.g., 01:00.0) or VFIO group"
                read -p "$(print_status "INPUT" "GPU passthrough [$GPU_PASSTHROUGH]: ")" new_gpu
                GPU_PASSTHROUGH="$new_gpu"
                print_status "SUCCESS" "GPU passthrough updated"
                ;;
            9)
                print_status "INFO" "Enter USB vendor:product IDs (e.g., 046d:c52b)"
                read -p "$(print_status "INPUT" "USB devices [$USB_DEVICES]: ")" new_usb
                USB_DEVICES="$new_usb"
                print_status "SUCCESS" "USB devices updated"
                ;;
            10)
                read -p "$(print_status "INPUT" "VNC port (5900=:0) [${VNC_PORT:-none}]: ")" new_vnc
                VNC_PORT="$new_vnc"
                print_status "SUCCESS" "VNC port updated"
                ;;
            11)
                read -p "$(print_status "INPUT" "SPICE port [${SPICE_PORT:-none}]: ")" new_spice
                SPICE_PORT="$new_spice"
                print_status "SUCCESS" "SPICE port updated"
                ;;
            12)
                read -p "$(print_status "INPUT" "Enable TPM? (true/false) [${TPM_ENABLED:-false}]: ")" new_tpm
                TPM_ENABLED="${new_tpm:-false}"
                print_status "SUCCESS" "TPM setting updated"
                ;;
            13)
                read -p "$(print_status "INPUT" "Custom QEMU arguments [$CUSTOM_ARGS]: ")" new_args
                CUSTOM_ARGS="$new_args"
                print_status "SUCCESS" "Custom arguments updated"
                ;;
            14)
                if is_vm_running "$vm_name"; then
                    print_status "ERROR" "Stop VM before changing username"
                else
                    read -p "$(print_status "INPUT" "New username [$USERNAME]: ")" new_user
                    if [[ -n "$new_user" ]] && validate_input "username" "$new_user"; then
                        USERNAME="$new_user"
                        setup_vm_image
                        print_status "SUCCESS" "Username updated (cloud-init regenerated)"
                    fi
                fi
                ;;
            15)
                if is_vm_running "$vm_name"; then
                    print_status "ERROR" "Stop VM before changing password"
                else
                    read -s -p "$(print_status "INPUT" "New password: ")" new_pass
                    echo
                    if [[ -n "$new_pass" ]]; then
                        PASSWORD="$new_pass"
                        setup_vm_image
                        print_status "SUCCESS" "Password updated (cloud-init regenerated)"
                    fi
                fi
                ;;
            16)
                if is_vm_running "$vm_name"; then
                    print_status "ERROR" "Stop VM before changing hostname"
                else
                    read -p "$(print_status "INPUT" "New hostname [$HOSTNAME]: ")" new_host
                    if [[ -n "$new_host" ]]; then
                        HOSTNAME="$new_host"
                        setup_vm_image
                        print_status "SUCCESS" "Hostname updated (cloud-init regenerated)"
                    fi
                fi
                ;;
            0)
                save_vm_config
                print_status "SUCCESS" "Configuration saved"
                return 0
                ;;
            *)
                print_status "ERROR" "Invalid option"
                ;;
        esac
    done
}

# ============================================
# VM Monitoring (NEW)
# ============================================

monitor_vm() {
    local vm_name="$1"

    if ! load_vm_config "$vm_name"; then
        return 1
    fi

    if ! is_vm_running "$vm_name"; then
        print_status "ERROR" "VM is not running"
        return 1
    fi

    local pid
    pid=$(get_vm_pid "$vm_name")

    echo
    print_status "INFO" "Monitoring VM: $vm_name (Press Ctrl+C to exit)"
    echo "════════════════════════════════════════════════════════"

    while true; do
        clear
        echo "VM: $vm_name | PID: $pid"
        echo "────────────────────────────────────────────────────────"

        if [[ -f "/proc/$pid/status" ]]; then
            local vm_rss
            local vm_vsz
            vm_rss=$(grep VmRSS /proc/$pid/status | awk '{print $2}')
            vm_vsz=$(grep VmSize /proc/$pid/status | awk '{print $2}')
            printf "Memory Usage:    %d MB (RSS) / %d MB (VSZ)\n" "$((vm_rss / 1024))" "$((vm_vsz / 1024))"
        fi

        if [[ -f "/proc/$pid/stat" ]]; then
            local cpu_usage
            cpu_usage=$(ps -p "$pid" -o %cpu --no-headers)
            printf "CPU Usage:       %s%%\n" "$cpu_usage"
        fi

        if [[ -S "$VM_DIR/$vm_name.monitor" ]]; then
            echo "info status" | socat - "UNIX-CONNECT:$VM_DIR/$vm_name.monitor" 2>/dev/null | grep -v "^QEMU"
        fi

        echo "────────────────────────────────────────────────────────"
        printf "Updated: %s\n" "$(date '+%Y-%m-%d %H:%M:%S')"

        sleep 2
    done
}

# ============================================
# Backup and Restore Functions (NEW)
# ============================================

backup_vm() {
    local vm_name="$1"

    if ! load_vm_config "$vm_name"; then
        return 1
    fi

    if is_vm_running "$vm_name"; then
        print_status "WARN" "VM is running. Stop for consistent backup? (y/n)"
        read -p "$(print_status "INPUT" "Choice: ")" stop_choice
        if [[ "$stop_choice" =~ ^[Yy]$ ]]; then
            stop_vm "$vm_name"
        fi
    fi

    local backup_name="${vm_name}_$(date +%Y%m%d_%H%M%S)"
    local backup_path="$BACKUP_DIR/$backup_name"

    mkdir -p "$backup_path"

    print_status "INFO" "Creating backup: $backup_name"

    # Copy disk image
    print_status "INFO" "Backing up disk image..."
    if ! cp "$IMG_FILE" "$backup_path/disk.qcow2"; then
        print_status "ERROR" "Failed to backup disk"
        return 1
    fi

    # Copy configuration
    cp "$VM_DIR/$vm_name.conf" "$backup_path/config.conf"

    # Copy cloud-init if exists
    [[ -f "$SEED_FILE" ]] && cp "$SEED_FILE" "$backup_path/seed.iso"

    # Create backup metadata
    cat > "$backup_path/metadata.txt" << EOF
VM Name: $vm_name
Backup Date: $(date '+%Y-%m-%d %H:%M:%S')
OS: $OS_TYPE $OS_VERSION
Memory: ${MEMORY}MB
CPUs: $CPUS
Disk Size: $DISK_SIZE
EOF

    # Compress backup
    print_status "INFO" "Compressing backup..."
    tar -czf "$BACKUP_DIR/${backup_name}.tar.gz" -C "$BACKUP_DIR" "$backup_name" 2>/dev/null
    rm -rf "$backup_path"

    local backup_size
    backup_size=$(du -h "$BACKUP_DIR/${backup_name}.tar.gz" | cut -f1)

    print_status "SUCCESS" "Backup created: ${backup_name}.tar.gz ($backup_size)"
    echo "  Location: $BACKUP_DIR/${backup_name}.tar.gz"
}

restore_vm() {
    echo
    print_status "INFO" "Available backups:"
    local backups=()
    local i=1

    while IFS= read -r backup; do
        if [[ -n "$backup" ]]; then
            backups+=("$backup")
            local size
            size=$(du -h "$BACKUP_DIR/$backup" | cut -f1)
            printf "  ${C_CYAN}%2d)${C_RESET} %s (%s)\n" "$i" "${backup%.tar.gz}" "$size"
            ((i++))
        fi
    done < <(find "$BACKUP_DIR" -name "*.tar.gz" -type f -printf "%f\n" 2>/dev/null | sort -r)

    if [[ ${#backups[@]} -eq 0 ]]; then
        print_status "ERROR" "No backups found"
        return 1
    fi

    echo
    read -p "$(print_status "INPUT" "Select backup (1-${#backups[@]}): ")" choice

    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [[ "$choice" -lt 1 ]] || [[ "$choice" -gt ${#backups[@]} ]]; then
        print_status "ERROR" "Invalid selection"
        return 1
    fi

    local backup_file="${backups[$((choice-1))]}"
    local backup_name="${backup_file%.tar.gz}"

    read -p "$(print_status "INPUT" "New VM name [$backup_name]: ")" new_name
    new_name="${new_name:-$backup_name}"

    if [[ -f "$VM_DIR/$new_name.conf" ]]; then
        print_status "ERROR" "VM '$new_name' already exists"
        return 1
    fi

    print_status "INFO" "Restoring backup..."

    # Extract backup
    local temp_dir="$BACKUP_DIR/restore_$$"
    mkdir -p "$temp_dir"

    if ! tar -xzf "$BACKUP_DIR/$backup_file" -C "$temp_dir" 2>/dev/null; then
        print_status "ERROR" "Failed to extract backup"
        rm -rf "$temp_dir"
        return 1
    fi

    # Load old config
    source "$temp_dir/$backup_name/config.conf"

    # Update VM name
    VM_NAME="$new_name"
    HOSTNAME="$new_name"
    IMG_FILE="$VM_DIR/$new_name.qcow2"
    SEED_FILE="$VM_DIR/$new_name-seed.iso"
    SSH_PORT=$(find_available_port 2222)
    CREATED="$(date '+%Y-%m-%d %H:%M:%S') (restored from $backup_name)"

    # Copy files
    cp "$temp_dir/$backup_name/disk.qcow2" "$IMG_FILE"
    [[ -f "$temp_dir/$backup_name/seed.iso" ]] && cp "$temp_dir/$backup_name/seed.iso" "$SEED_FILE"

    # Save new config
    save_vm_config

    # Cleanup
    rm -rf "$temp_dir"

    print_status "SUCCESS" "VM restored as '$new_name'"
    echo "  Start with: ./vm.sh start $new_name"
}

list_backups() {
    echo
    print_status "INFO" "Available Backups:"
    echo "════════════════════════════════════════════════════════"

    local found=0
    while IFS= read -r backup; do
        if [[ -n "$backup" ]]; then
            local size
            size=$(du -h "$BACKUP_DIR/$backup" | cut -f1)
            local date_str
            date_str=$(basename "$backup" .tar.gz | grep -oP '\d{8}_\d{6}')
            if [[ -n "$date_str" ]]; then
                local formatted_date="${date_str:0:4}-${date_str:4:2}-${date_str:6:2} ${date_str:9:2}:${date_str:11:2}:${date_str:13:2}"
                printf "  %s - %s (%s)\n" "$formatted_date" "$(basename "$backup" .tar.gz)" "$size"
            else
                printf "  %s (%s)\n" "$(basename "$backup" .tar.gz)" "$size"
            fi
            found=1
        fi
    done < <(find "$BACKUP_DIR" -name "*.tar.gz" -type f -printf "%f\n" 2>/dev/null | sort -r)

    if [[ $found -eq 0 ]]; then
        echo "  No backups found"
    fi

    echo "════════════════════════════════════════════════════════"
    echo
}

# ============================================
# Export/Import Functions (NEW)
# ============================================

export_vm() {
    local vm_name="$1"

    if ! load_vm_config "$vm_name"; then
        return 1
    fi

    if is_vm_running "$vm_name"; then
        print_status "ERROR" "Stop the VM before exporting"
        return 1
    fi

    read -p "$(print_status "INPUT" "Export path [./${vm_name}.ova]: ")" export_path
    export_path="${export_path:-${vm_name}.ova}"

    print_status "INFO" "Exporting VM to OVA format..."

    local temp_dir="/tmp/vm_export_$$"
    mkdir -p "$temp_dir"

    # Copy and convert disk
    print_status "INFO" "Converting disk to VMDK..."
    qemu-img convert -O vmdk "$IMG_FILE" "$temp_dir/${vm_name}.vmdk" 2>/dev/null

    # Create OVF descriptor
    cat > "$temp_dir/${vm_name}.ovf" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1">
  <VirtualSystem ovf:id="$vm_name">
    <Info>VM: $vm_name</Info>
    <Name>$vm_name</Name>
    <OperatingSystemSection>
      <Info>$OS_TYPE $OS_VERSION</Info>
    </OperatingSystemSection>
    <VirtualHardwareSection>
      <Item>
        <rasd:Description>CPU</rasd:Description>
        <rasd:ElementName>$CPUS virtual CPU</rasd:ElementName>
        <rasd:InstanceID>1</rasd:InstanceID>
        <rasd:VirtualQuantity>$CPUS</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:Description>Memory</rasd:Description>
        <rasd:ElementName>${MEMORY}MB memory</rasd:ElementName>
        <rasd:InstanceID>2</rasd:InstanceID>
        <rasd:VirtualQuantity>$MEMORY</rasd:VirtualQuantity>
      </Item>
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>
EOF

    # Create OVA (tar archive)
    print_status "INFO" "Creating OVA archive..."
    tar -cf "$export_path" -C "$temp_dir" "${vm_name}.ovf" "${vm_name}.vmdk" 2>/dev/null

    # Cleanup
    rm -rf "$temp_dir"

    local size
    size=$(du -h "$export_path" | cut -f1)
    print_status "SUCCESS" "VM exported: $export_path ($size)"
}

# ============================================
# Quick Create VM
# ============================================

quick_create_vm() {
    local os_choice="$1"
    local vm_name="${2:-}"

    local os_data="${OS_OPTIONS[$os_choice]:-}"
    if [[ -z "$os_data" ]]; then
        print_status "ERROR" "Unknown OS: $os_choice"
        echo "Available options:"
        printf '%s\n' "${!OS_OPTIONS[@]}" | sort | sed 's/^/  /'
        return 1
    fi

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
    SHARED_FOLDERS=""
    GPU_PASSTHROUGH=""
    USB_DEVICES=""
    NETWORK_MODE="user"
    BRIDGE_NAME=""
    CUSTOM_ARGS=""
    VNC_PORT=""
    SPICE_PORT=""
    TPM_ENABLED="false"
    UEFI_ENABLED="false"
    SECURE_BOOT="false"
    IMG_FILE="$VM_DIR/$VM_NAME.qcow2"
    SEED_FILE="$VM_DIR/$VM_NAME-seed.iso"
    CREATED="$(date '+%Y-%m-%d %H:%M:%S')"

    if [[ -f "$VM_DIR/$VM_NAME.conf" ]]; then
        print_status "ERROR" "VM '$VM_NAME' already exists"
        return 1
    fi

    print_status "INFO" "Quick creating: $VM_NAME ($OS_TYPE $OS_VERSION)"

    if ! setup_vm_image; then
        return 1
    fi

    save_vm_config

    echo
    print_status "SUCCESS" "VM '$VM_NAME' created!"
    echo "  Start:    ./vm.sh start $VM_NAME"
    echo "  SSH:      ssh -p $SSH_PORT $USERNAME@localhost"
    echo "  User:     $USERNAME"
    echo "  Password: $PASSWORD"
}

# ============================================
# Interactive Create VM
# ============================================

create_new_vm() {
    print_status "INFO" "Select Operating System:"
    echo

    local os_keys=()
    local i=1
    while IFS= read -r os; do
        os_keys+=("$os")
        printf "  ${C_CYAN}%2d)${C_RESET} %s\n" "$i" "$os"
        ((i++))
    done < <(printf '%s\n' "${!OS_OPTIONS[@]}" | sort)
    echo

    local os_count=${#os_keys[@]}
    local choice
    while true; do
        read -p "$(print_status "INPUT" "Select OS (1-$os_count): ")" choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le "$os_count" ]]; then
            break
        fi
        print_status "ERROR" "Invalid selection"
    done

    local os="${os_keys[$((choice-1))]}"
    IFS='|' read -r OS_TYPE OS_VERSION CODENAME IMG_URL DEFAULT_HOSTNAME DEFAULT_USERNAME DEFAULT_PASSWORD <<< "${OS_OPTIONS[$os]}"
    print_status "SUCCESS" "Selected: $os"
    echo

    # VM Name
    while true; do
        read -p "$(print_status "INPUT" "VM name [$DEFAULT_HOSTNAME]: ")" VM_NAME
        VM_NAME="${VM_NAME:-$DEFAULT_HOSTNAME}"
        if validate_input "name" "$VM_NAME"; then
            if [[ ! -f "$VM_DIR/$VM_NAME.conf" ]]; then
                break
            fi
            print_status "ERROR" "VM '$VM_NAME' already exists"
        fi
    done

    # Hostname
    read -p "$(print_status "INPUT" "Hostname [$VM_NAME]: ")" HOSTNAME
    HOSTNAME="${HOSTNAME:-$VM_NAME}"

    # Username
    read -p "$(print_status "INPUT" "Username [$DEFAULT_USERNAME]: ")" USERNAME
    USERNAME="${USERNAME:-$DEFAULT_USERNAME}"

    # Password
    read -s -p "$(print_status "INPUT" "Password [$DEFAULT_PASSWORD]: ")" PASSWORD
    echo
    PASSWORD="${PASSWORD:-$DEFAULT_PASSWORD}"

    # Disk Size
    read -p "$(print_status "INPUT" "Disk size [$DEFAULT_DISK]: ")" DISK_SIZE
    DISK_SIZE="${DISK_SIZE:-$DEFAULT_DISK}"

    # Memory
    read -p "$(print_status "INPUT" "RAM in MB [$DEFAULT_MEMORY]: ")" MEMORY
    MEMORY="${MEMORY:-$DEFAULT_MEMORY}"

    # CPUs
    read -p "$(print_status "INPUT" "CPU cores [$DEFAULT_CPUS]: ")" CPUS
    CPUS="${CPUS:-$DEFAULT_CPUS}"

    # SSH Port
    SSH_PORT=$(find_available_port 2222)
    read -p "$(print_status "INPUT" "SSH port [$SSH_PORT]: ")" input_port
    SSH_PORT="${input_port:-$SSH_PORT}"

    # Port Forwards
    GUI_MODE=false
    read -p "$(print_status "INPUT" "Port forwards (e.g., 8080:80,3000:3000): ")" PORT_FORWARDS

    # Initialize advanced options
    SHARED_FOLDERS=""
    GPU_PASSTHROUGH=""
    USB_DEVICES=""
    NETWORK_MODE="user"
    BRIDGE_NAME=""
    CUSTOM_ARGS=""
    VNC_PORT=""
    SPICE_PORT=""
    TPM_ENABLED="false"
    UEFI_ENABLED="false"
    SECURE_BOOT="false"

    IMG_FILE="$VM_DIR/$VM_NAME.qcow2"
    SEED_FILE="$VM_DIR/$VM_NAME-seed.iso"
    CREATED="$(date '+%Y-%m-%d %H:%M:%S')"

    echo
    print_status "INFO" "Summary:"
    echo "  Name: $VM_NAME | OS: $OS_TYPE $OS_VERSION"
    echo "  RAM: ${MEMORY}MB | CPUs: $CPUS | Disk: $DISK_SIZE"
    echo "  User: $USERNAME | SSH Port: $SSH_PORT"
    echo

    read -p "$(print_status "INPUT" "Create VM? [Y/n]: ")" confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        print_status "INFO" "Cancelled"
        return 1
    fi

    if ! setup_vm_image; then
        return 1
    fi

    save_vm_config

    echo
    print_status "SUCCESS" "VM '$VM_NAME' created!"
    print_status "INFO" "Start with option 2 from menu or: ./vm.sh start $VM_NAME"
}

# ============================================
# Additional Functions
# ============================================

clone_vm() {
    local source="$1"

    if ! load_vm_config "$source"; then
        return 1
    fi

    read -p "$(print_status "INPUT" "New VM name: ")" new_name
    if [[ -z "$new_name" ]]; then
        return 1
    fi

    if [[ -f "$VM_DIR/$new_name.conf" ]]; then
        print_status "ERROR" "VM '$new_name' already exists"
        return 1
    fi

    local src_img="$IMG_FILE"
    VM_NAME="$new_name"
    HOSTNAME="$new_name"
    IMG_FILE="$VM_DIR/$new_name.qcow2"
    SEED_FILE="$VM_DIR/$new_name-seed.iso"
    SSH_PORT=$(find_available_port "$SSH_PORT")
    CREATED="$(date '+%Y-%m-%d %H:%M:%S') (cloned from $source)"

    print_status "INFO" "Cloning disk image..."
    if ! cp "$src_img" "$IMG_FILE"; then
        print_status "ERROR" "Failed to clone disk"
        return 1
    fi

    setup_vm_image
    save_vm_config
    print_status "SUCCESS" "Cloned '$source' to '$new_name'"
}

resize_disk() {
    local vm="$1"

    if ! load_vm_config "$vm"; then
        return 1
    fi

    if is_vm_running "$vm"; then
        print_status "ERROR" "Please stop the VM first"
        return 1
    fi

    read -p "$(print_status "INPUT" "New size (e.g., 50G): ")" new_size
    if ! validate_input "size" "$new_size"; then
        return 1
    fi

    if qemu-img resize "$IMG_FILE" "$new_size" 2>/dev/null; then
        DISK_SIZE="$new_size"
        save_vm_config
        print_status "SUCCESS" "Disk resized to $new_size"
        print_status "INFO" "Run 'sudo resize2fs /dev/vda1' inside VM to expand filesystem"
    else
        print_status "ERROR" "Failed to resize disk"
    fi
}

create_snapshot() {
    local vm="$1"

    if ! load_vm_config "$vm"; then
        return 1
    fi

    read -p "$(print_status "INPUT" "Snapshot name: ")" name
    if [[ -z "$name" ]]; then
        return 1
    fi

    if qemu-img snapshot -c "$name" "$IMG_FILE" 2>/dev/null; then
        print_status "SUCCESS" "Snapshot '$name' created"
    else
        print_status "ERROR" "Failed to create snapshot"
    fi
}

list_snapshots() {
    local vm="$1"

    if ! load_vm_config "$vm"; then
        return 1
    fi

    echo
    print_status "INFO" "Snapshots for $vm:"
    qemu-img snapshot -l "$IMG_FILE" 2>/dev/null || echo "  No snapshots found"
    echo
}

restore_snapshot() {
    local vm="$1"

    if ! load_vm_config "$vm"; then
        return 1
    fi

    if is_vm_running "$vm"; then
        print_status "ERROR" "Please stop the VM first"
        return 1
    fi

    list_snapshots "$vm"
    read -p "$(print_status "INPUT" "Snapshot name to restore: ")" name

    if qemu-img snapshot -a "$name" "$IMG_FILE" 2>/dev/null; then
        print_status "SUCCESS" "Restored snapshot '$name'"
    else
        print_status "ERROR" "Failed to restore snapshot"
    fi
}

delete_snapshot() {
    local vm="$1"

    if ! load_vm_config "$vm"; then
        return 1
    fi

    list_snapshots "$vm"
    read -p "$(print_status "INPUT" "Snapshot name to delete: ")" name

    if qemu-img snapshot -d "$name" "$IMG_FILE" 2>/dev/null; then
        print_status "SUCCESS" "Deleted snapshot '$name'"
    else
        print_status "ERROR" "Failed to delete snapshot"
    fi
}

show_system_info() {
    echo
    print_status "INFO" "System Information"
    echo "════════════════════════════════════════════════════════"
    printf "  Hostname:    %s\n" "$(hostname)"
    printf "  Kernel:      %s\n" "$(uname -r)"
    printf "  Total CPUs:  %s\n" "$TOTAL_CPUS"
    printf "  Total RAM:   %sMB\n" "$TOTAL_MEM"
    printf "  Free RAM:    %s\n" "$(free -h 2>/dev/null | awk '/Mem:/{print $4}')"
    printf "  KVM:         %s\n" "$KVM_AVAILABLE"
    printf "  QEMU:        %s\n" "$(qemu-system-x86_64 --version 2>/dev/null | head -1 | awk '{print $4}')"
    printf "  VM Dir:      %s\n" "$VM_DIR"
    [[ "$IDX_ENV" == "true" ]] && printf "  IDX Mode:    Enabled\n"
    echo "════════════════════════════════════════════════════════"
    echo
}

select_vm() {
    local prompt="$1"
    shift
    local vms=("$@")
    local count=${#vms[@]}

    if [[ "$count" -eq 0 ]]; then
        print_status "ERROR" "No VMs available"
        return 1
    fi

    read -p "$(print_status "INPUT" "$prompt (1-$count): ")" num
    if [[ "$num" =~ ^[0-9]+$ ]] && [[ "$num" -ge 1 ]] && [[ "$num" -le "$count" ]]; then
        echo "${vms[$((num-1))]}"
        return 0
    fi
    return 1
}

# ============================================
# Command Line Interface
# ============================================

cli_usage() {
    cat << EOF
Usage: $0 [command] [args]

Commands:
  list                    List all VMs
  create                  Interactive VM creation
  quick <os> [name]       Quick create VM
  start <vm>              Start VM in foreground
  startbg <vm>            Start VM in background
  stop <vm>               Stop VM
  delete <vm>             Delete VM
  info <vm>               Show VM info
  edit <vm>               Edit VM configuration (NEW)
  monitor <vm>            Monitor VM stats (NEW)
  clone <vm>              Clone VM
  resize <vm>             Resize disk
  snapshot <vm>           Create snapshot
  snaplist <vm>           List snapshots
  restore <vm>            Restore snapshot
  snapdel <vm>            Delete snapshot
  backup <vm>             Backup VM (NEW)
  restore-backup          Restore from backup (NEW)
  list-backups            List all backups (NEW)
  export <vm>             Export VM to OVA (NEW)
  system                  System info
  oses                    List available OSes
  help                    Show this help

Examples:
  $0 quick "Ubuntu 24.04 LTS (Noble)" myserver
  $0 edit myserver
  $0 monitor myserver
  $0 backup myserver
  $0 start myserver

EOF
}

list_available_oses() {
    echo
    print_status "INFO" "Available Operating Systems:"
    echo
    printf '%s\n' "${!OS_OPTIONS[@]}" | sort | while read -r os; do
        IFS='|' read -r type ver _ <<< "${OS_OPTIONS[$os]}"
        printf "  - %s\n" "$os"
    done
    echo
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
            print_status "INFO" "Virtual Machines ($count):"
            for i in "${!vms[@]}"; do
                local st="○" col="$C_RED"
                if is_vm_running "${vms[$i]}"; then
                    st="●"
                    col="$C_GREEN"
                fi
                printf "  ${C_CYAN}%2d)${C_RESET} %-30s ${col}%s${C_RESET}\n" "$((i+1))" "${vms[$i]}" "$st"
            done
            echo
        fi

        echo "╔═════════════════════════════════════════════════════════╗"
        echo "║                    Main Menu v5.0                       ║"
        echo "╠═════════════════════════════════════════════════════════╣"
        echo "║  1) Create VM          2) Start (foreground)            ║"
        echo "║  3) Start (bg)         4) Stop VM                       ║"
        echo "║  5) VM Info            6) Edit VM (NEW)                 ║"
        echo "║  7) Clone VM           8) Monitor VM (NEW)              ║"
        echo "║  9) Snapshots         10) Resize Disk                   ║"
        echo "║ 11) Delete VM         12) Backup VM (NEW)               ║"
        echo "║ 13) Restore Backup    14) List Backups                  ║"
        echo "║ 15) Export VM          s) System Info                   ║"
        echo "║  o) List OSes          0) Exit                          ║"
        echo "╚═════════════════════════════════════════════════════════╝"

        read -p "$(print_status "INPUT" "Choice: ")" choice

        case "$choice" in
            1)
                create_new_vm
                ;;
            2)
                if [[ $count -gt 0 ]]; then
                    local vm
                    vm=$(select_vm "Start VM" "${vms[@]}") && start_vm "$vm"
                else
                    print_status "ERROR" "No VMs available"
                fi
                ;;
            3)
                if [[ $count -gt 0 ]]; then
                    local vm
                    vm=$(select_vm "Start in background" "${vms[@]}") && start_vm_background "$vm"
                else
                    print_status "ERROR" "No VMs available"
                fi
                ;;
            4)
                if [[ $count -gt 0 ]]; then
                    local vm
                    vm=$(select_vm "Stop VM" "${vms[@]}") && stop_vm "$vm"
                else
                    print_status "ERROR" "No VMs available"
                fi
                ;;
            5)
                if [[ $count -gt 0 ]]; then
                    local vm
                    vm=$(select_vm "VM Info" "${vms[@]}") && show_vm_info "$vm"
                else
                    print_status "ERROR" "No VMs available"
                fi
                ;;
            6)
                if [[ $count -gt 0 ]]; then
                    local vm
                    vm=$(select_vm "Edit VM" "${vms[@]}") && edit_vm "$vm"
                else
                    print_status "ERROR" "No VMs available"
                fi
                ;;
            7)
                if [[ $count -gt 0 ]]; then
                    local vm
                    vm=$(select_vm "Clone VM" "${vms[@]}") && clone_vm "$vm"
                else
                    print_status "ERROR" "No VMs available"
                fi
                ;;
            8)
                if [[ $count -gt 0 ]]; then
                    local vm
                    vm=$(select_vm "Monitor VM" "${vms[@]}") && monitor_vm "$vm"
                else
                    print_status "ERROR" "No VMs available"
                fi
                ;;
            9)
                if [[ $count -gt 0 ]]; then
                    local vm
                    vm=$(select_vm "Snapshot VM" "${vms[@]}") || continue
                    echo "  1) Create  2) List  3) Restore  4) Delete"
                    read -p "$(print_status "INPUT" "Action: ")" act
                    case "$act" in
                        1) create_snapshot "$vm" ;;
                        2) list_snapshots "$vm" ;;
                        3) restore_snapshot "$vm" ;;
                        4) delete_snapshot "$vm" ;;
                    esac
                else
                    print_status "ERROR" "No VMs available"
                fi
                ;;
            10)
                if [[ $count -gt 0 ]]; then
                    local vm
                    vm=$(select_vm "Resize VM" "${vms[@]}") && resize_disk "$vm"
                else
                    print_status "ERROR" "No VMs available"
                fi
                ;;
            11)
                if [[ $count -gt 0 ]]; then
                    local vm
                    vm=$(select_vm "Delete VM" "${vms[@]}") && delete_vm "$vm"
                else
                    print_status "ERROR" "No VMs available"
                fi
                ;;
            12)
                if [[ $count -gt 0 ]]; then
                    local vm
                    vm=$(select_vm "Backup VM" "${vms[@]}") && backup_vm "$vm"
                else
                    print_status "ERROR" "No VMs available"
                fi
                ;;
            13)
                restore_vm
                ;;
            14)
                list_backups
                ;;
            15)
                if [[ $count -gt 0 ]]; then
                    local vm
                    vm=$(select_vm "Export VM" "${vms[@]}") && export_vm "$vm"
                else
                    print_status "ERROR" "No VMs available"
                fi
                ;;
            s|S)
                show_system_info
                ;;
            o|O)
                list_available_oses
                ;;
            0|q|Q)
                print_status "INFO" "Goodbye!"
                exit 0
                ;;
            *)
                print_status "ERROR" "Invalid option"
                ;;
        esac

        echo
        read -p "Press Enter to continue..."
    done
}

# ============================================
# OS Options - Verified Cloud Image URLs
# ============================================

declare -A OS_OPTIONS=(
    # Ubuntu - Supported Versions
    ["Ubuntu 18.04 LTS (Bionic)"]="ubuntu|18.04|bionic|https://cloud-images.ubuntu.com/bionic/current/bionic-server-cloudimg-amd64.img|ubuntu18|ubuntu|ubuntu"
    ["Ubuntu 20.04 LTS (Focal)"]="ubuntu|20.04|focal|https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img|ubuntu20|ubuntu|ubuntu"
    ["Ubuntu 22.04 LTS (Jammy)"]="ubuntu|22.04|jammy|https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img|ubuntu22|ubuntu|ubuntu"
    ["Ubuntu 24.04 LTS (Noble)"]="ubuntu|24.04|noble|https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img|ubuntu24|ubuntu|ubuntu"
    ["Ubuntu 25.04 (Plucky)"]="ubuntu|25.04|plucky|https://cloud-images.ubuntu.com/plucky/current/plucky-server-cloudimg-amd64.img|ubuntu25|ubuntu|ubuntu"

    # Debian
    ["Debian 10 (Buster)"]="debian|10|buster|https://cloud.debian.org/images/cloud/buster/latest/debian-10-generic-amd64.qcow2|debian10|debian|debian"
    ["Debian 11 (Bullseye)"]="debian|11|bullseye|https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-generic-amd64.qcow2|debian11|debian|debian"
    ["Debian 12 (Bookworm)"]="debian|12|bookworm|https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2|debian12|debian|debian"
    ["Debian 13 (Trixie)"]="debian|13|trixie|https://cloud.debian.org/images/cloud/trixie/daily/latest/debian-13-generic-amd64-daily.qcow2|debian13|debian|debian"
    ["Debian Sid (Unstable)"]="debian|sid|sid|https://cloud.debian.org/images/cloud/sid/daily/latest/debian-sid-generic-amd64-daily.qcow2|debiansid|debian|debian"

    # Fedora
    ["Fedora 39"]="fedora|39|39|https://download.fedoraproject.org/pub/fedora/linux/releases/39/Cloud/x86_64/images/Fedora-Cloud-Base-39-1.5.x86_64.qcow2|fedora39|fedora|fedora"
    ["Fedora 40"]="fedora|40|40|https://download.fedoraproject.org/pub/fedora/linux/releases/40/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-40-1.14.x86_64.qcow2|fedora40|fedora|fedora"
    ["Fedora 41"]="fedora|41|41|https://download.fedoraproject.org/pub/fedora/linux/releases/41/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-41-1.4.x86_64.qcow2|fedora41|fedora|fedora"

    # Enterprise RHEL-based
    ["CentOS Stream 9"]="centos|stream9|stream9|https://cloud.centos.org/centos/9-stream/x86_64/images/CentOS-Stream-GenericCloud-9-latest.x86_64.qcow2|centos9|cloud-user|centos"
    ["AlmaLinux 8"]="almalinux|8|8|https://repo.almalinux.org/almalinux/8/cloud/x86_64/images/AlmaLinux-8-GenericCloud-latest.x86_64.qcow2|alma8|almalinux|almalinux"
    ["AlmaLinux 9"]="almalinux|9|9|https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-latest.x86_64.qcow2|alma9|almalinux|almalinux"
    ["Rocky Linux 8"]="rocky|8|8|https://download.rockylinux.org/pub/rocky/8/images/x86_64/Rocky-8-GenericCloud.latest.x86_64.qcow2|rocky8|rocky|rocky"
    ["Rocky Linux 9"]="rocky|9|9|https://download.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud.latest.x86_64.qcow2|rocky9|rocky|rocky"
    ["Oracle Linux 8"]="oracle|8|ol8|https://yum.oracle.com/templates/OracleLinux/OL8/u10/x86_64/OL8U10_x86_64-kvm-b234.qcow2|oracle8|root|oracle"
    ["Oracle Linux 9"]="oracle|9|ol9|https://yum.oracle.com/templates/OracleLinux/OL9/u5/x86_64/OL9U5_x86_64-kvm-b253.qcow2|oracle9|root|oracle"

    # Arch-based
    ["Arch Linux"]="arch|rolling|latest|https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2|archlinux|arch|arch"
    ["Manjaro (Arch-based)"]="manjaro|rolling|latest|https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2|manjaro|manjaro|manjaro"

    # Lightweight
    ["Alpine Linux 3.18"]="alpine|3.18|v3.18|https://dl-cdn.alpinelinux.org/alpine/v3.18/releases/cloud/nocloud_alpine-3.18.9-x86_64-bios-cloudinit-r0.qcow2|alpine318|alpine|alpine"
    ["Alpine Linux 3.19"]="alpine|3.19|v3.19|https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/cloud/nocloud_alpine-3.19.4-x86_64-bios-cloudinit-r0.qcow2|alpine319|alpine|alpine"
    ["Alpine Linux 3.20"]="alpine|3.20|v3.20|https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/cloud/nocloud_alpine-3.20.3-x86_64-bios-cloudinit-r0.qcow2|alpine320|alpine|alpine"
    ["Alpine Linux 3.21"]="alpine|3.21|v3.21|https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/cloud/nocloud_alpine-3.21.0-x86_64-bios-cloudinit-r0.qcow2|alpine321|alpine|alpine"

    # openSUSE
    ["openSUSE Leap 15.5"]="opensuse|15.5|leap155|https://download.opensuse.org/distribution/leap/15.5/appliances/openSUSE-Leap-15.5-Minimal-VM.x86_64-Cloud.qcow2|opensuse155|root|opensuse"
    ["openSUSE Leap 15.6"]="opensuse|15.6|leap156|https://download.opensuse.org/distribution/leap/15.6/appliances/openSUSE-Leap-15.6-Minimal-VM.x86_64-Cloud.qcow2|opensuse156|root|opensuse"

    # Cloud Provider
    ["Amazon Linux 2023"]="amazonlinux|2023|al2023|https://cdn.amazonlinux.com/al2023/os-images/2023.6.20241121.0/kvm/al2023-kvm-2023.6.20241121.0-kernel-6.1-x86_64.xfs.gpt.qcow2|amazonlinux|ec2-user|amazon"

    # Zorin OS
    ["Zorin OS 17 (Ubuntu 24.04 Base)"]="zorin|17|noble|https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img|zorin17|zorin|zorin"
)

# ============================================
# Entry Point
# ============================================

# Handle CLI arguments
if [[ $# -gt 0 ]]; then
    case "$1" in
        list)
            get_vm_list
            ;;
        create)
            display_header
            check_dependencies
            check_kvm
            create_new_vm
            ;;
        quick)
            shift
            if [[ $# -lt 1 ]]; then
                print_status "ERROR" "Usage: $0 quick <os> [name]"
                list_available_oses
                exit 1
            fi
            check_dependencies
            check_kvm
            quick_create_vm "$@"
            ;;
        start)
            shift
            [[ -z "${1:-}" ]] && { print_status "ERROR" "VM name required"; exit 1; }
            check_kvm
            start_vm "$1"
            ;;
        startbg)
            shift
            [[ -z "${1:-}" ]] && { print_status "ERROR" "VM name required"; exit 1; }
            check_kvm
            start_vm_background "$1"
            ;;
        stop)
            shift
            [[ -z "${1:-}" ]] && { print_status "ERROR" "VM name required"; exit 1; }
            stop_vm "$1"
            ;;
        delete)
            shift
            [[ -z "${1:-}" ]] && { print_status "ERROR" "VM name required"; exit 1; }
            delete_vm "$1"
            ;;
        info)
            shift
            [[ -z "${1:-}" ]] && { print_status "ERROR" "VM name required"; exit 1; }
            show_vm_info "$1"
            ;;
        edit)
            shift
            [[ -z "${1:-}" ]] && { print_status "ERROR" "VM name required"; exit 1; }
            edit_vm "$1"
            ;;
        monitor)
            shift
            [[ -z "${1:-}" ]] && { print_status "ERROR" "VM name required"; exit 1; }
            monitor_vm "$1"
            ;;
        clone)
            shift
            [[ -z "${1:-}" ]] && { print_status "ERROR" "VM name required"; exit 1; }
            clone_vm "$1"
            ;;
        resize)
            shift
            [[ -z "${1:-}" ]] && { print_status "ERROR" "VM name required"; exit 1; }
            resize_disk "$1"
            ;;
        snapshot)
            shift
            [[ -z "${1:-}" ]] && { print_status "ERROR" "VM name required"; exit 1; }
            create_snapshot "$1"
            ;;
        snaplist)
            shift
            [[ -z "${1:-}" ]] && { print_status "ERROR" "VM name required"; exit 1; }
            list_snapshots "$1"
            ;;
        restore)
            shift
            [[ -z "${1:-}" ]] && { print_status "ERROR" "VM name required"; exit 1; }
            restore_snapshot "$1"
            ;;
        snapdel)
            shift
            [[ -z "${1:-}" ]] && { print_status "ERROR" "VM name required"; exit 1; }
            delete_snapshot "$1"
            ;;
        backup)
            shift
            [[ -z "${1:-}" ]] && { print_status "ERROR" "VM name required"; exit 1; }
            backup_vm "$1"
            ;;
        restore-backup)
            restore_vm
            ;;
        list-backups)
            list_backups
            ;;
        export)
            shift
            [[ -z "${1:-}" ]] && { print_status "ERROR" "VM name required"; exit 1; }
            export_vm "$1"
            ;;
        system)
            check_kvm
            show_system_info
            ;;
        oses)
            list_available_oses
            ;;
        help|--help|-h)
            cli_usage
            ;;
        *)
            print_status "ERROR" "Unknown command: $1"
            cli_usage
            exit 1
            ;;
    esac
    exit 0
fi

# Interactive mode
display_header
print_status "INFO" "Initializing..."
check_dependencies
check_kvm
echo
main_menu
