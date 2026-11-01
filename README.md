# PiDash

[![CI](https://github.com/vctralrwilliamson/pidash/actions/workflows/ci.yml/badge.svg)](https://github.com/vctralrwilliamson/pidash/actions/workflows/ci.yml)

A home network dashboard for a Raspberry Pi. It watches who is on your network, flags likely threats, checks your home servers, sleeps to a galaxy landscape, and reads you a status report in a robotic voice every morning.

Built and tested on a Raspberry Pi 3 Model B+ (1 GB RAM) running Raspberry Pi OS (64-bit, Debian 13 "trixie").

## Features

| Feature | How it works |
|---|---|
| **Device discovery** | `arp-scan` every 2 minutes. The first scan becomes your trusted baseline. |
| **New-device alerts** | Any device not in the baseline raises an alert (on screen, spoken, optional phone push). |
| **Spoofing detection** | Alerts when two devices claim one IP address, or when the router's MAC address changes. |
| **Risky and new ports** | Hourly `nmap` connect scan of common ports. Flags Telnet, SMB, RDP, VNC, open databases, and any newly opened port. |
| **Server status** | Devices with server ports (SSH, web, Ollama, Plex, …) are discovered automatically. Mark one **Watch** to be alerted when it goes down. |
| **Galaxy sleep screen** | After 5 idle minutes the screen shows a procedurally painted Milky Way over mountain ridges, with the date, time, and network status. A new sky every day. |
| **6:00 AM briefing** | The screen wakes and a male robotic voice (`espeak-ng`) reads devices, overnight newcomers, alerts, servers, and Pi temperature. |

No third-party Python packages: only the standard library, `arp-scan`, `nmap`, and `espeak-ng`.

## Install

On the Pi, as your normal user (not root):

```bash
git clone https://github.com/vctralrwilliamson/pidash.git pidash-src
cd pidash-src
bash install.sh
sudo reboot
```

The installer copies the app to `~/pidash`, creates a systemd service (`pidash`) and a 6:00 AM timer (`pidash-briefing.timer`), and opens the dashboard full-screen at login.

Open the dashboard from any device on your network at `http://<pi-ip>:8080`.

If the full-screen view doesn't start at login on newer Raspberry Pi OS (labwc desktop), add it to the labwc autostart:

```bash
mkdir -p ~/.config/labwc
echo "sh -c 'sleep 10; chromium --kiosk --noerrdialogs --incognito http://localhost:8080' &" >> ~/.config/labwc/autostart
```

## Configuration

Edit `~/pidash/config.json`, then run `sudo systemctl restart pidash`.

| Key | Default | Meaning |
|---|---|---|
| `bind` | `0.0.0.0` | Address the dashboard listens on. Use `127.0.0.1` to allow only the Pi itself. |
| `port` | `8080` | Dashboard port |
| `scan_interval_sec` | `120` | Seconds between device scans |
| `port_scan_minutes` | `60` | Minutes between port scans |
| `idle_sleep_min` | `5` | Idle minutes before the galaxy screen |
| `voice` | `en-us+m3` | `espeak-ng` voice. Try `en-us+m1` … `m7`. |
| `voice_speed` / `voice_pitch` | `145` / `25` | Lower pitch sounds more robotic |
| `voice_alerts` | `true` | Speak alerts out loud |
| `quiet_hours` | `[22, 6]` | No spoken alerts between these hours |
| `ntfy_topic` | `""` | Optional phone push through [ntfy](https://ntfy.sh). Use a long random topic name. |
| `servers` | `[]` | Extra servers to monitor: `{"name", "host", "port"}` |

Test the briefing any time: `python3 ~/pidash/briefing.py` (add `--print` to print it without speaking).

## Security notes

- **Scans only your own network.** Only run this on networks you own or are allowed to monitor.
- **No login on the dashboard.** Anyone on your LAN can rename or trust devices. Never forward port 8080 from your router to the internet. Set `bind` to `127.0.0.1` if only the Pi's screen should see it.
- **Least privilege.** The service runs as your normal user. Only `arp-scan` gets the `cap_net_raw` and `cap_net_admin` capabilities it needs; nothing runs as root.
- **Cross-site requests blocked.** Changes require a JSON request, which other websites can't send from your browser without a preflight the server never approves.
- **Your data stays local.** Device lists and alerts live in `~/pidash/data/`, which is git-ignored. Nothing leaves the Pi unless you set an `ntfy_topic`.
- **ntfy topics are public by name.** Anyone who guesses your topic can read the alerts, so make it long and random.

## Files

```
monitor.py         scanner, alerts, server checks, web server
briefing.py        6:00 AM spoken report
static/index.html  dashboard + galaxy sleep screen
config.json        settings
install.sh         installer (packages, services, kiosk autostart)
tests/             smoke test with fake network tools (no real scanning)
.github/           CI: lint, tests, secret scan, CodeQL, releases
```

## CI/CD

Every push and pull request runs on GitHub Actions:

1. **Lint:** ruff (including bandit security rules), shellcheck, JSON and JavaScript syntax.
2. **Smoke test** on Python 3.11, 3.12, and 3.13. Fake `arp-scan` and `nmap` simulate a network with a new device, a spoofed router, and an open Telnet port, and the test checks that each alert fires once, the security protections hold, and the morning briefing builds.
3. **Secret scan** of the full git history with gitleaks.
4. **CodeQL** security analysis (public repo only).

To publish a release, tag a version. CI builds the install bundle, adds a SHA-256 checksum, and attaches both to a GitHub release:

```bash
git tag v1.0.0
git push origin v1.0.0
```

Run the tests locally with `bash tests/smoke_test.sh`.

## Uninstall

```bash
sudo systemctl disable --now pidash pidash-briefing.timer
sudo rm /etc/systemd/system/pidash*.service /etc/systemd/system/pidash-briefing.timer
rm -rf ~/pidash ~/.config/autostart/pidash-kiosk.desktop
```
