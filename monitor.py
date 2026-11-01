#!/usr/bin/env python3
"""PiDash: home network monitor.

Finds devices (arp-scan), raises threat alerts, checks home servers,
speaks alerts, and serves the dashboard on http://<pi-ip>:8080
"""
import json
import os
import re
import socket
import subprocess
import threading
import time
import urllib.request
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE = Path(__file__).resolve().parent
DATA = BASE / "data"
DATA.mkdir(exist_ok=True)
DB_FILE = DATA / "devices.json"
EV_FILE = DATA / "events.json"
STATIC = BASE / "static"


def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_json(path, obj):
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=1)
    os.replace(tmp, path)


CFG = load_json(BASE / "config.json", {})


def cfg(key, default):
    return CFG.get(key, default)


# Ports that are risky to leave open on a home network.
RISKY = {21: "FTP", 23: "Telnet", 135: "MS-RPC", 139: "NetBIOS", 445: "SMB",
         1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 6379: "Redis",
         9200: "Elasticsearch", 27017: "MongoDB"}
# Ports that mean "this device is serving something".
SERVER_PORTS = {22: "SSH", 53: "DNS", 80: "Web", 443: "HTTPS", 445: "File share",
                631: "Printer", 1883: "MQTT", 3000: "Web app", 5000: "Web app",
                6333: "Qdrant", 8080: "Web app", 8096: "Jellyfin",
                8123: "Home Assistant", 8443: "HTTPS", 9000: "Web app",
                11434: "Ollama", 32400: "Plex"}
SCAN_PORTS = sorted(set(RISKY) | set(SERVER_PORTS))

lock = threading.RLock()
speak_lock = threading.Lock()
first_run = not DB_FILE.exists()
db = load_json(DB_FILE, {"devices": {}, "meta": {}})
events = load_json(EV_FILE, [])
rt = {"iface": None, "my_ip": None, "my_mac": None, "gateway": None,
      "last_scan": None, "last_port_scan": None, "servers": {}, "wake": 0,
      "started": time.time(), "scan_error": None}


def log(*a):
    print(datetime.now().strftime("%H:%M:%S"), *a, flush=True)


def run(cmd, timeout=60):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        log("command failed:", cmd[0], e)
        return ""


# ---------------------------------------------------------------- alerts
def in_quiet_hours():
    start, end = cfg("quiet_hours", [22, 6])
    h = datetime.now().hour
    return (h >= start or h < end) if start > end else (start <= h < end)


def speak(text):
    env = dict(os.environ)
    env.setdefault("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    cmd = ["espeak-ng", "-v", cfg("voice", "en-us+m3"), "-s", str(cfg("voice_speed", 145)),
           "-p", str(cfg("voice_pitch", 25)), text]
    with speak_lock:
        try:
            subprocess.run(cmd, env=env, timeout=120)
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            log("speak failed:", e, "|", text)


def push(title, msg, sev):
    topic = cfg("ntfy_topic", "").strip()
    if not topic:
        return
    prio = {"crit": "5", "warn": "4"}.get(sev, "3")
    try:
        req = urllib.request.Request(f"https://ntfy.sh/{topic}", data=msg.encode(),
                                     headers={"Title": title, "Priority": prio,
                                              "Tags": "warning" if sev != "info" else "information_source"})
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:  # network trouble must never stop monitoring
        log("push failed:", e)


def add_event(kind, sev, msg, mac=None, spoken=None):
    ev = {"id": int(time.time() * 1000), "t": time.time(), "kind": kind,
          "sev": sev, "msg": msg, "mac": mac, "read": False}
    with lock:
        events.append(ev)
        del events[:-500]
        save_json(EV_FILE, events)
    log(f"[{sev}] {msg}")
    if sev in ("warn", "crit"):
        def notify():
            push("PiDash alert" if sev == "warn" else "PiDash CRITICAL", msg, sev)
            if cfg("voice_alerts", True) and not in_quiet_hours():
                speak(spoken or ("Alert. " + msg))
        threading.Thread(target=notify, daemon=True).start()


# ---------------------------------------------------------------- network
def net_info():
    m = re.search(r"default via (\S+) dev (\S+)", run(["ip", "route", "show", "default"]))
    if m:
        rt["gateway"], rt["iface"] = m.group(1), m.group(2)
    if rt["iface"]:
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", run(["ip", "-4", "-o", "addr", "show", "dev", rt["iface"]]))
        rt["my_ip"] = m.group(1) if m else None
        try:
            rt["my_mac"] = Path(f"/sys/class/net/{rt['iface']}/address").read_text().strip().lower()
        except OSError:
            pass


def random_mac(mac):
    return bool(int(mac[1], 16) & 2)


def arp_scan():
    cmd = ["arp-scan", "--localnet", "--retry=3"]
    if rt["iface"]:
        cmd += ["-I", rt["iface"]]
    for flag, path in (("--ouifile", "/usr/share/arp-scan/ieee-oui.txt"),
                       ("--macfile", "/etc/arp-scan/mac-vendor.txt")):
        if os.path.exists(path):
            cmd.append(f"{flag}={path}")
    out = run(cmd, timeout=90)
    if "Operation not permitted" in out or not out:
        rt["scan_error"] = "arp-scan failed (permissions?)"
    else:
        rt["scan_error"] = None
    found = []
    for line in out.splitlines():
        m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17})\s*(.*)$", line.strip(), re.I)
        if m:
            vendor = re.sub(r"\((Unknown[^)]*|DUP: \d+)\)", "", m.group(3)).strip()
            found.append((m.group(1), m.group(2).lower(), vendor))
    return found


def scan():
    global first_run
    net_info()
    found = arp_scan()
    if rt["my_ip"] and rt["my_mac"]:
        found.append((rt["my_ip"], rt["my_mac"], "Raspberry Pi (this dashboard)"))
    now = time.time()
    ip_macs = {}
    with lock:
        devs = db["devices"]
        for ip, mac, vendor in found:
            ip_macs.setdefault(ip, set()).add(mac)
            d = devs.get(mac)
            if d is None:
                rnd = random_mac(mac)
                label = "This Pi" if mac == rt["my_mac"] else (vendor or ("Phone/tablet (private address)" if rnd else "Unknown device"))
                d = devs[mac] = {"mac": mac, "ip": ip, "vendor": vendor, "label": label,
                                 "trusted": first_run or mac == rt["my_mac"], "watch": False,
                                 "random": rnd, "first_seen": now, "last_seen": now,
                                 "ports": [], "ports_scanned": None}
                if not d["trusted"]:
                    extra = " It uses a private address, so it is probably a phone or tablet." if rnd else ""
                    add_event("new_device", "warn",
                              f"New device joined: {label} at {ip} ({mac}).{extra}", mac,
                              spoken=f"Alert. New device joined the network. {label}.")
            elif d["ip"] != ip:
                add_event("ip_change", "info", f"{d['label']} moved from {d['ip']} to {ip}.", mac)
                d["ip"] = ip
            if vendor and not d.get("vendor"):
                d["vendor"] = vendor
            d["last_seen"] = now

        # alert once when a conflict starts, again only after it clears and returns
        active = rt.setdefault("conflicts", set())
        current = {(ip, tuple(sorted(macs))) for ip, macs in ip_macs.items() if len(macs) > 1}
        for ip, macs in current - active:
            add_event("ip_conflict", "crit",
                      f"Two devices claim {ip}: {', '.join(macs)}. This can mean ARP spoofing.",
                      spoken="Critical alert. Two devices are claiming the same address. Possible spoofing attack.")
        for ip, _macs in active - current:
            add_event("ip_conflict_end", "info", f"Address conflict on {ip} has cleared.")
        rt["conflicts"] = current

        gw = rt["gateway"]
        gw_macs = ip_macs.get(gw)
        if gw_macs and len(gw_macs) == 1:
            gw_mac = next(iter(gw_macs))
            old = db["meta"].get("gateway_mac")
            if old and old != gw_mac:
                add_event("gateway_change", "crit",
                          f"Router {gw} changed MAC address from {old} to {gw_mac}. Possible ARP spoofing, or the router was replaced.",
                          spoken="Critical alert. The router's hardware address changed. Possible spoofing attack.")
            db["meta"]["gateway_mac"] = gw_mac

        if first_run and found:
            add_event("baseline", "info",
                      f"Baseline saved: {len(found)} devices marked as known. Rename them on the dashboard.")
            first_run = False
        rt["last_scan"] = now
        save_json(DB_FILE, db)


def online(d):
    return time.time() - d["last_seen"] < cfg("offline_after_min", 15) * 60


def port_scan():
    with lock:
        targets = [dict(d) for d in db["devices"].values() if online(d) and d["mac"] != rt["my_mac"]]
    ports_arg = ",".join(map(str, SCAN_PORTS))
    for t in targets:
        out = run(["nmap", "-sT", "-Pn", "-T4", "-p", ports_arg, "--open", "-oG", "-", t["ip"]], timeout=180)
        if not out:
            continue
        ports = sorted({int(p) for p in re.findall(r"(\d+)/open/tcp", out)})
        with lock:
            d = db["devices"].get(t["mac"])
            if not d or d["ip"] != t["ip"]:
                continue
            old = set(d.get("ports") or [])
            new = [p for p in ports if p not in old]
            def names(ps):
                return ", ".join(f"{p} {RISKY.get(p) or SERVER_PORTS.get(p, '')}".strip() for p in ps)
            risky_new = [p for p in new if p in RISKY]
            if d.get("ports_scanned") and new:
                sev = "crit" if risky_new else "warn"
                add_event("new_port", sev, f"New open port on {d['label']} ({d['ip']}): {names(new)}.", d["mac"],
                          spoken=f"Alert. New open port on {d['label']}.")
            elif not d.get("ports_scanned") and risky_new:
                add_event("risky_port", "warn", f"{d['label']} ({d['ip']}) exposes risky services: {names(risky_new)}.",
                          d["mac"], spoken=f"Warning. {d['label']} has a risky service open.")
            d["ports"] = ports
            d["ports_scanned"] = time.time()
            save_json(DB_FILE, db)
    rt["last_port_scan"] = time.time()


def tcp_up(host, port):
    try:
        with socket.create_connection((host, int(port)), timeout=2):
            return True
    except OSError:
        return False


def check_servers():
    wanted = {}
    for s in cfg("servers", []):
        wanted[f"cfg:{s['host']}:{s['port']}"] = {"name": s["name"], "host": s["host"], "ports": [int(s["port"])],
                                                  "services": [SERVER_PORTS.get(int(s["port"]), str(s["port"]))],
                                                  "alerts": True}
    with lock:
        for d in db["devices"].values():
            sp = [p for p in d.get("ports") or [] if p in SERVER_PORTS]
            if sp and d["mac"] != rt["my_mac"]:
                wanted[f"dev:{d['mac']}"] = {"name": d["label"], "host": d["ip"], "ports": sp,
                                             "services": sorted({SERVER_PORTS[p] for p in sp}),
                                             "alerts": d.get("watch", False), "mac": d["mac"]}
    for key, s in wanted.items():
        up = any(tcp_up(s["host"], p) for p in s["ports"][:3])
        prev = rt["servers"].get(key)
        s["up"] = up
        s["since"] = prev["since"] if prev and prev["up"] == up else time.time()
        if prev and prev["up"] != up and s["alerts"]:
            if up:
                add_event("server_up", "info", f"Server {s['name']} ({s['host']}) is back online.")
            else:
                add_event("server_down", "crit", f"Server {s['name']} ({s['host']}) is offline.",
                          s.get("mac"), spoken=f"Critical alert. Server {s['name']} is offline.")
        rt["servers"][key] = s
    for key in list(rt["servers"]):
        if key not in wanted:
            del rt["servers"][key]


def pi_stats():
    st = {}
    try:
        st["temp_c"] = round(int(Path("/sys/class/thermal/thermal_zone0/temp").read_text()) / 1000, 1)
    except (OSError, ValueError):
        st["temp_c"] = None
    try:
        mem = dict(re.findall(r"^(\w+):\s+(\d+)", Path("/proc/meminfo").read_text(), re.M))
        st["mem_pct"] = round(100 * (1 - int(mem["MemAvailable"]) / int(mem["MemTotal"])))
        st["load"] = round(os.getloadavg()[0], 2)
        st["uptime_h"] = round(float(Path("/proc/uptime").read_text().split()[0]) / 3600, 1)
    except (OSError, KeyError, ValueError):
        pass
    return st


def status():
    with lock:
        devs = []
        for d in db["devices"].values():
            x = dict(d)
            x["online"] = online(d)
            x["risky"] = [p for p in d.get("ports") or [] if p in RISKY]
            devs.append(x)
        devs.sort(key=lambda d: (not d["online"], not d["mac"] == rt["my_mac"], d["label"].lower()))
        evs = list(reversed(events[-150:]))
        unread = sum(1 for e in events if not e["read"] and e["sev"] != "info")
    servers = sorted(rt["servers"].values(), key=lambda s: (s["up"], s["name"].lower()))
    return {"now": time.time(), "network": {k: rt[k] for k in ("iface", "my_ip", "gateway")},
            "last_scan": rt["last_scan"], "last_port_scan": rt["last_port_scan"], "scan_error": rt["scan_error"],
            "devices": devs, "servers": servers, "events": evs, "unread": unread,
            "pi": pi_stats(), "wake": rt["wake"],
            "ui": {"idle_sleep_min": cfg("idle_sleep_min", 5)}}


# ---------------------------------------------------------------- loops
def loop(fn, every, delay=0):
    time.sleep(delay)
    while True:
        try:
            fn()
        except Exception as e:  # keep the monitor alive no matter what
            log("error in", fn.__name__, repr(e))
        time.sleep(every)


def scan_cycle():
    scan()
    check_servers()


# ---------------------------------------------------------------- web
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/api/status":
            return self.send(200, status())
        if path in ("/", "/index.html"):
            path = "/index.html"
        f = (STATIC / path.lstrip("/")).resolve()
        if STATIC.resolve() in f.parents and f.is_file():
            ctype = {".html": "text/html; charset=utf-8", ".js": "text/javascript",
                     ".css": "text/css", ".png": "image/png"}.get(f.suffix, "application/octet-stream")
            return self.send(200, f.read_bytes(), ctype)
        self.send(404, {"error": "not found"})

    def do_POST(self):
        if not (self.headers.get("Content-Type") or "").startswith("application/json"):
            return self.send(415, {"error": "send application/json"})
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self.send(400, {"error": "bad length"})
        if n > 10000:
            return self.send(413, {"error": "too large"})
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            return self.send(400, {"error": "bad json"})
        path = self.path.split("?")[0]
        if path == "/api/device":
            with lock:
                d = db["devices"].get(str(body.get("mac", "")).lower())
                if not d:
                    return self.send(404, {"error": "unknown device"})
                if "label" in body:
                    d["label"] = str(body["label"]).strip()[:60] or d["label"]
                for k in ("trusted", "watch"):
                    if k in body:
                        d[k] = bool(body[k])
                save_json(DB_FILE, db)
            return self.send(200, {"ok": True})
        if path == "/api/forget":
            with lock:
                db["devices"].pop(str(body.get("mac", "")).lower(), None)
                save_json(DB_FILE, db)
            return self.send(200, {"ok": True})
        if path == "/api/read":
            with lock:
                for e in events:
                    e["read"] = True
                save_json(EV_FILE, events)
            return self.send(200, {"ok": True})
        if path == "/api/wake":
            rt["wake"] = time.time()
            return self.send(200, {"ok": True})
        self.send(404, {"error": "not found"})


def main():
    net_info()
    log(f"PiDash starting on {rt['iface']} {rt['my_ip']} (gateway {rt['gateway']})")
    threading.Thread(target=loop, args=(scan_cycle, cfg("scan_interval_sec", 120)), daemon=True).start()
    threading.Thread(target=loop, args=(port_scan, cfg("port_scan_minutes", 60) * 60, 45), daemon=True).start()
    port = cfg("port", 8080)
    log(f"dashboard: http://{rt['my_ip'] or 'localhost'}:{port}")
    ThreadingHTTPServer((cfg("bind", "0.0.0.0"), port), Handler).serve_forever()


if __name__ == "__main__":
    main()
