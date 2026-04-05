#!/bin/bash
set -euo pipefail

# ============================================================
# Proxy Dispatcher - Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/mnnb123/proxy-dispatcher/main/scripts/install.sh | sudo bash
# ============================================================

APP_NAME="proxy-dispatcher"
REPO="mnnb123/proxy-dispatcher"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/proxy-dispatcher"
LOG_DIR="/var/log/proxy-dispatcher"
SERVICE_NAME="proxy-dispatcher"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()   { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[x]${NC} $1"; exit 1; }
info()  { echo -e "${CYAN}[i]${NC} $1"; }

# ============================================================
# Pre-flight checks
# ============================================================

echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}   Proxy Dispatcher Installer${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

# Must be root
if [ "$EUID" -ne 0 ]; then
    error "Vui long chay voi sudo: sudo bash install.sh"
fi

# Must be Linux
if [ "$(uname -s)" != "Linux" ]; then
    error "Script chi ho tro Linux"
fi

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  BINARY_SUFFIX="linux-amd64" ;;
    aarch64) BINARY_SUFFIX="linux-arm64" ;;
    arm64)   BINARY_SUFFIX="linux-arm64" ;;
    *)       error "Architecture khong ho tro: $ARCH (can amd64 hoac arm64)" ;;
esac

info "OS: $(uname -s) | Arch: $ARCH -> $BINARY_SUFFIX"

# Check dependencies
for cmd in curl jq; do
    if ! command -v "$cmd" &>/dev/null; then
        warn "$cmd chua cai, dang cai dat..."
        apt-get update -qq && apt-get install -y -qq "$cmd"
    fi
done

# ============================================================
# Download latest release
# ============================================================

info "Dang tim phien ban moi nhat..."

LATEST_URL="https://api.github.com/repos/${REPO}/releases/latest"
RELEASE_JSON=$(curl -fsSL "$LATEST_URL" 2>/dev/null) || error "Khong the ket noi GitHub. Kiem tra mang."

VERSION=$(echo "$RELEASE_JSON" | jq -r '.tag_name')
if [ "$VERSION" = "null" ] || [ -z "$VERSION" ]; then
    error "Khong tim thay release nao tren GitHub"
fi

DOWNLOAD_URL=$(echo "$RELEASE_JSON" | jq -r ".assets[] | select(.name | contains(\"$BINARY_SUFFIX\")) | .browser_download_url")
if [ -z "$DOWNLOAD_URL" ]; then
    error "Khong tim thay binary cho $BINARY_SUFFIX"
fi

log "Phien ban: $VERSION"
info "Dang tai binary..."

TMP_FILE=$(mktemp)
curl -fsSL -o "$TMP_FILE" "$DOWNLOAD_URL" || error "Tai binary that bai"

# ============================================================
# Check existing installation (upgrade)
# ============================================================

UPGRADE=false
if [ -f "${INSTALL_DIR}/${APP_NAME}" ]; then
    CURRENT_VERSION=$(${INSTALL_DIR}/${APP_NAME} --version 2>/dev/null || echo "unknown")
    warn "Da cai dat phien ban: $CURRENT_VERSION"
    warn "Dang nang cap len: $VERSION"
    UPGRADE=true

    # Stop service truoc khi upgrade
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        info "Dang dung service..."
        systemctl stop "$SERVICE_NAME"
    fi

    # Backup binary cu
    cp "${INSTALL_DIR}/${APP_NAME}" "${INSTALL_DIR}/${APP_NAME}.bak"
fi

# ============================================================
# Install binary
# ============================================================

info "Dang cai dat binary..."
mv "$TMP_FILE" "${INSTALL_DIR}/${APP_NAME}"
chmod 755 "${INSTALL_DIR}/${APP_NAME}"
log "Binary: ${INSTALL_DIR}/${APP_NAME}"

# ============================================================
# Create directories
# ============================================================

mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

mkdir -p "${CONFIG_DIR}/backups"
chmod 700 "${CONFIG_DIR}/backups"

mkdir -p "$LOG_DIR"
chmod 755 "$LOG_DIR"

log "Config: $CONFIG_DIR"
log "Logs: $LOG_DIR"

# ============================================================
# Generate default config (chi khi cai lan dau)
# ============================================================

CONFIG_FILE="${CONFIG_DIR}/config.json"

if [ ! -f "$CONFIG_FILE" ]; then
    info "Tao config mac dinh..."

    # Detect VPS IP
    VPS_IP=$(curl -fsSL https://checkip.amazonaws.com 2>/dev/null || curl -fsSL https://ifconfig.me 2>/dev/null || echo "0.0.0.0")
    VPS_IP=$(echo "$VPS_IP" | tr -d '[:space:]')

    # Detect RAM -> auto config
    TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    TOTAL_RAM_MB=$((TOTAL_RAM_KB / 1024))

    if [ "$TOTAL_RAM_MB" -lt 1024 ]; then
        RING_BUFFER=300; CLEAR_SEC=180
    elif [ "$TOTAL_RAM_MB" -lt 2048 ]; then
        RING_BUFFER=1000; CLEAR_SEC=300
    elif [ "$TOTAL_RAM_MB" -lt 4096 ]; then
        RING_BUFFER=2000; CLEAR_SEC=600
    else
        RING_BUFFER=5000; CLEAR_SEC=600
    fi

    info "VPS IP: $VPS_IP | RAM: ${TOTAL_RAM_MB}MB -> Ring Buffer: $RING_BUFFER"

    # Tao config bang binary
    ${INSTALL_DIR}/${APP_NAME} --init-config \
        --vps-ip "$VPS_IP" \
        --ring-buffer "$RING_BUFFER" \
        --clear-sec "$CLEAR_SEC" \
        --config "$CONFIG_FILE"

    log "Config tao xong: $CONFIG_FILE"

    # Hien thi thong tin admin
    echo ""
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}  THONG TIN DANG NHAP MAC DINH${NC}"
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}  URL:      http://${VPS_IP}:8000${NC}"
    echo -e "${YELLOW}  Username: admin${NC}"
    echo -e "${YELLOW}  Password: admin${NC}"
    echo ""
    echo -e "${YELLOW}  HAY DOI MAT KHAU NGAY SAU KHI${NC}"
    echo -e "${YELLOW}  DANG NHAP LAN DAU!${NC}"
    echo -e "${YELLOW}========================================${NC}"
    echo ""
else
    log "Config da ton tai, giu nguyen: $CONFIG_FILE"
fi

# ============================================================
# Install systemd service
# ============================================================

SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

cat > "$SERVICE_FILE" << 'EOF'
[Unit]
Description=Proxy Dispatcher Service
Documentation=https://github.com/mnnb123/proxy-dispatcher
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/proxy-dispatcher --config /etc/proxy-dispatcher/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
LimitNOFILE=65535
LimitNPROC=65535

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/proxy-dispatcher /var/log/proxy-dispatcher
PrivateTmp=true

# Environment
Environment=GOMAXPROCS=0

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=proxy-dispatcher

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME" --quiet
log "Systemd service cai dat xong"

# ============================================================
# Configure firewall (neu ufw active)
# ============================================================

if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
    info "Dang cau hinh firewall (ufw)..."
    ufw allow 8000/tcp comment "Proxy Dispatcher Web Panel" >/dev/null 2>&1
    ufw allow 30001:30100/tcp comment "Proxy Dispatcher Output Ports" >/dev/null 2>&1
    log "Firewall: port 8000 + 30001-30100 da mo"
else
    info "ufw khong active, bo qua firewall config"
fi

# ============================================================
# Optimize system (sysctl)
# ============================================================

SYSCTL_FILE="/etc/sysctl.d/99-proxy-dispatcher.conf"
if [ ! -f "$SYSCTL_FILE" ]; then
    info "Toi uu kernel parameters..."
    cat > "$SYSCTL_FILE" << 'EOF'
# Proxy Dispatcher - Kernel Optimization
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
fs.file-max = 1000000
EOF
    sysctl --system >/dev/null 2>&1
    log "Kernel parameters toi uu xong"
fi

# Increase open file limit
LIMITS_FILE="/etc/security/limits.d/proxy-dispatcher.conf"
if [ ! -f "$LIMITS_FILE" ]; then
    cat > "$LIMITS_FILE" << 'EOF'
* soft nofile 65535
* hard nofile 65535
root soft nofile 65535
root hard nofile 65535
EOF
    log "File limits toi uu xong"
fi

# ============================================================
# Start service
# ============================================================

info "Dang khoi dong service..."
systemctl start "$SERVICE_NAME"
sleep 2

if systemctl is-active --quiet "$SERVICE_NAME"; then
    log "Service dang chay!"
else
    error "Service khong khoi dong duoc. Xem log: journalctl -u $SERVICE_NAME -n 50"
fi

# ============================================================
# Final summary
# ============================================================

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}       CAI DAT HOAN TAT!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "  Web Panel:  http://${VPS_IP:-YOUR_IP}:8000"
echo -e "  Binary:     ${INSTALL_DIR}/${APP_NAME}"
echo -e "  Config:     ${CONFIG_FILE}"
echo -e "  Logs:       ${LOG_DIR}/"
echo -e "  Service:    systemctl status ${SERVICE_NAME}"
echo ""
echo -e "  Lenh huu ich:"
echo -e "    Xem log:     journalctl -u ${SERVICE_NAME} -f"
echo -e "    Restart:     systemctl restart ${SERVICE_NAME}"
echo -e "    Stop:        systemctl stop ${SERVICE_NAME}"
echo ""
