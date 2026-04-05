#!/bin/bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${RED}========================================${NC}"
echo -e "${RED}  Proxy Dispatcher - Go cai dat${NC}"
echo -e "${RED}========================================${NC}"

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Can chay voi sudo${NC}"; exit 1
fi

read -p "Ban co chac muon go cai dat? (y/N): " confirm
if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
    echo "Da huy."; exit 0
fi

echo ""

# Stop + disable service
if systemctl is-active --quiet proxy-dispatcher 2>/dev/null; then
    systemctl stop proxy-dispatcher
    echo -e "${GREEN}[+]${NC} Service da dung"
fi
systemctl disable proxy-dispatcher --quiet 2>/dev/null || true
rm -f /etc/systemd/system/proxy-dispatcher.service
systemctl daemon-reload
echo -e "${GREEN}[+]${NC} Service da go"

# Remove binary
rm -f /usr/local/bin/proxy-dispatcher
rm -f /usr/local/bin/proxy-dispatcher.bak
echo -e "${GREEN}[+]${NC} Binary da xoa"

# Ask about config + logs
read -p "Xoa config (/etc/proxy-dispatcher/)? (y/N): " del_config
if [ "$del_config" = "y" ] || [ "$del_config" = "Y" ]; then
    rm -rf /etc/proxy-dispatcher
    echo -e "${GREEN}[+]${NC} Config da xoa"
else
    echo -e "${YELLOW}[!]${NC} Config giu nguyen: /etc/proxy-dispatcher/"
fi

read -p "Xoa logs (/var/log/proxy-dispatcher/)? (y/N): " del_logs
if [ "$del_logs" = "y" ] || [ "$del_logs" = "Y" ]; then
    rm -rf /var/log/proxy-dispatcher
    echo -e "${GREEN}[+]${NC} Logs da xoa"
else
    echo -e "${YELLOW}[!]${NC} Logs giu nguyen: /var/log/proxy-dispatcher/"
fi

# Remove sysctl + limits
rm -f /etc/sysctl.d/99-proxy-dispatcher.conf
rm -f /etc/security/limits.d/proxy-dispatcher.conf
sysctl --system >/dev/null 2>&1

echo ""
echo -e "${GREEN}Go cai dat hoan tat!${NC}"
