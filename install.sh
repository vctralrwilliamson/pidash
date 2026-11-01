#!/usr/bin/env bash
# PiDash installer. Run on the Pi as your normal user (not root):  bash install.sh
set -euo pipefail

if [ "$(id -u)" -eq 0 ]; then
  echo "Run this as your normal user (e.g. pi), not with sudo. It asks for sudo when needed."; exit 1
fi

ME="$(id -un)"; MYUID="$(id -u)"
SRC="$(cd "$(dirname "$0")" && pwd)"
APP="$HOME/pidash"

echo "==> Installing packages"
sudo apt-get update -qq
sudo apt-get install -y arp-scan nmap espeak-ng python3 libcap2-bin

echo "==> Copying files to $APP"
mkdir -p "$APP/static" "$APP/data"
if [ "$SRC" -ef "$APP" ]; then
  echo "    already in $APP, nothing to copy"
else
  cp "$SRC/monitor.py" "$SRC/briefing.py" "$APP/"
  cp "$SRC/static/index.html" "$APP/static/"
  if [ -f "$APP/config.json" ]; then
    echo "    keeping your existing config.json"
  else
    cp "$SRC/config.json" "$APP/"
  fi
fi

echo "==> Letting arp-scan run without root"
sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v arp-scan)"

echo "==> Keeping Wi-Fi awake (power saving off)"
CON="$(nmcli -t -f NAME,DEVICE con show --active | awk -F: '$2=="wlan0"{print $1; exit}')"
if [ -n "$CON" ]; then sudo nmcli connection modify "$CON" 802-11-wireless.powersave 2 || true; fi

echo "==> Monitor service"
sudo tee /etc/systemd/system/pidash.service >/dev/null <<EOF
[Unit]
Description=PiDash home network monitor
Wants=network-online.target
After=network-online.target

[Service]
User=$ME
WorkingDirectory=$APP
Environment=XDG_RUNTIME_DIR=/run/user/$MYUID
ExecStart=/usr/bin/python3 $APP/monitor.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

echo "==> 6:00 AM briefing"
sudo tee /etc/systemd/system/pidash-briefing.service >/dev/null <<EOF
[Unit]
Description=PiDash morning briefing
After=pidash.service

[Service]
Type=oneshot
User=$ME
Environment=XDG_RUNTIME_DIR=/run/user/$MYUID
ExecStart=/usr/bin/python3 $APP/briefing.py
EOF
sudo tee /etc/systemd/system/pidash-briefing.timer >/dev/null <<EOF
[Unit]
Description=PiDash briefing every morning at 6:00

[Timer]
OnCalendar=*-*-* 06:00:00

[Install]
WantedBy=timers.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now pidash.service pidash-briefing.timer
sudo systemctl restart pidash.service

echo "==> Screen: no blanking (the galaxy screen replaces it)"
if command -v raspi-config >/dev/null; then sudo raspi-config nonint do_blanking 1 || true; fi

echo "==> Full-screen dashboard at login"
BROWSER="$(command -v chromium || command -v chromium-browser || true)"
if [ -n "$BROWSER" ]; then
  mkdir -p "$HOME/.config/autostart"
  cat > "$HOME/.config/autostart/pidash-kiosk.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=PiDash kiosk
Exec=sh -c 'sleep 8; $BROWSER --kiosk --noerrdialogs --disable-infobars --incognito --password-store=basic --check-for-update-interval=31536000 http://localhost:8080'
X-GNOME-Autostart-enabled=true
EOF
else
  echo "    Chromium not found; open http://localhost:8080 in any browser instead."
fi

sleep 3
IP="$(hostname -I | awk '{print $1}')"
echo
if systemctl is-active --quiet pidash.service; then
  echo "PiDash is running."
  echo "  Dashboard:      http://$IP:8080   (from your phone or PC)"
  echo "  Test the voice: python3 $APP/briefing.py"
  echo "  Logs:           journalctl -u pidash -f"
  echo "  Reboot to start the full-screen view:  sudo reboot"
else
  echo "Service did not start. Check:  journalctl -u pidash -n 50"
fi
