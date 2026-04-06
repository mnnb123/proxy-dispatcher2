# Proxy Dispatcher

Bien VPS Ubuntu thanh tram phat lai proxy. Nhan proxy dau vao, phat ra
nhieu port tren IP VPS. Ho tro HTTP + SOCKS5. Quan ly qua Web Panel.

## Cai dat (1 lenh)

```bash
curl -fsSL https://raw.githubusercontent.com/mnnb123/proxy-dispatcher2/main/scripts/install.sh | sudo bash
```

Sau khi cai, truy cap `http://YOUR_VPS_IP:8000` de quan ly.

> Dang nhap mac dinh: `admin` / `admin` -- hay doi mat khau ngay!

## Yeu cau he thong

- Ubuntu 22.04+ (hoac Debian 11+)
- RAM toi thieu: 512MB (khuyen nghi 1GB+)
- CPU: 1 core+
- Architecture: amd64 hoac arm64

## Tinh nang

- **Proxy Forwarding** -- HTTP + SOCKS5 tren cung port
- **Proxy Groups** -- nhom proxy theo quoc gia, map voi port range
- **5 Rotation Modes** -- Round Robin, Random, Sticky, Least Connection, Weighted
- **Health Check** -- tu dong kiem tra proxy alive/dead/slow
- **Domain Bypass** -- bypass domain khoi proxy (tiet kiem bandwidth)
- **Extension Bypass** -- bypass file media, image, software
- **Auto Bypass Size** -- tu chuyen DIRECT khi response vuot nguong
- **Block List** -- chan domain khong mong muon
- **IP Whitelist** -- chi cho phep IP cu the ket noi
- **Bandwidth Budget** -- gioi han bandwidth proxy/ngay
- **Real-time Report** -- live traffic, charts, top domains (toi uu RAM)
- **Multi-User** -- Admin, Operator, Viewer roles
- **2FA (TOTP)** -- Google Authenticator support
- **API Tokens** -- REST API cho automation
- **Multi-VPS Sync** -- master-slave config sync
- **Backup/Restore** -- auto backup, export/import config
- **1 lenh cai dat** -- auto detect VPS, toi uu kernel

## Lenh thuong dung

```bash
# Xem log
journalctl -u proxy-dispatcher -f

# Restart service
sudo systemctl restart proxy-dispatcher

# Reset admin password (khi bi lockout)
sudo proxy-dispatcher --reset-admin

# Go cai dat
curl -fsSL https://raw.githubusercontent.com/mnnb123/proxy-dispatcher2/main/scripts/uninstall.sh | sudo bash
```

## Cau truc files

```
/usr/local/bin/proxy-dispatcher          # Binary
/etc/proxy-dispatcher/config.json        # Config
/etc/proxy-dispatcher/backups/           # Auto backups
/var/log/proxy-dispatcher/               # Access logs
```

## Build tu source

```bash
git clone https://github.com/mnnb123/proxy-dispatcher2
cd proxy-dispatcher
make build
# Binary: dist/proxy-dispatcher-linux-amd64
```

## License

MIT
