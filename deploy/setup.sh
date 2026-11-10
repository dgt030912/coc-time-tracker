#!/bin/bash
# Sets up (or re-applies) the app on a Debian VM. Safe to run repeatedly; the VM's startup script runs it on every boot.
#   - app code:  /srv/coc            (git clone of this repo, pulled every 5 minutes by deploy/update.sh)
#   - data:      /var/lib/coc-timer  (users, sessions, per-user villages; owned by the "coc" system user)
#   - server.py on 127.0.0.1:8080 behind Caddy, which serves HTTPS at <external-ip>.sslip.io
# Create a login with:  sudo -u coc DATA_DIR=/var/lib/coc-timer python3 /srv/coc/server.py adduser NAME
set -euo pipefail

REPO=https://github.com/dgt030912/coc-time-tracker.git
APP=/srv/coc
DATA=/var/lib/coc-timer

if ! command -v caddy >/dev/null || ! command -v git >/dev/null || ! command -v python3 >/dev/null; then
  apt-get update -q
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q caddy git python3
fi

id coc >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin coc
install -d -o coc -g coc -m 700 "$DATA"

[ -d "$APP/.git" ] || git clone -q "$REPO" "$APP"
git config --global --add safe.directory "$APP" 2>/dev/null || true

cat > /etc/systemd/system/coc-timer.service <<EOF
[Unit]
Description=CoC upgrade timer backend
After=network.target

[Service]
User=coc
Group=coc
Environment=DATA_DIR=$DATA
Environment=HOST=127.0.0.1
Environment=PORT=8080
ExecStart=/usr/bin/python3 $APP/server.py
Restart=always
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

IP=$(curl -sf -H 'Metadata-Flavor: Google' \
  http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip)
if ! [[ "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Could not read the VM's external IP (got: '$IP'); leaving Caddy config unchanged" >&2
  exit 1
fi
HOST="${IP//./-}.sslip.io"
cat > /etc/caddy/Caddyfile <<EOF
${HOST} {
  encode gzip
  reverse_proxy 127.0.0.1:8080
}
EOF

rm -f /etc/cron.d/coc-pull  # replaced by update.sh
echo "*/5 * * * * root $APP/deploy/update.sh >/dev/null 2>&1" > /etc/cron.d/coc-update

systemctl daemon-reload
systemctl enable -q coc-timer caddy
systemctl restart coc-timer
systemctl reload caddy 2>/dev/null || systemctl restart caddy
echo "Serving https://${HOST}"
