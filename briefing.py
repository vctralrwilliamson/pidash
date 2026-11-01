#!/usr/bin/env python3
"""PiDash morning briefing: wakes the screen and reads the network status aloud.

Run by a systemd timer at 6:00 AM. Test any time with:  python3 briefing.py
Print the text without speaking:                          python3 briefing.py --print
"""
import json
import os
import subprocess
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parent
try:
    CFG = json.loads((BASE / "config.json").read_text())
except (OSError, json.JSONDecodeError):
    CFG = {}
URL = f"http://127.0.0.1:{CFG.get('port', 8080)}"


def api(path, post=False):
    req = urllib.request.Request(URL + path, data=b"{}" if post else None,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def ordinal(n):
    return f"{n}{'th' if 11 <= n % 100 <= 13 else {1: 'st', 2: 'nd', 3: 'rd'}.get(n % 10, 'th')}"


def plural(n, word):
    return f"{n} {word}{'' if n == 1 else 's'}"


def compose(st):
    now = datetime.now()
    h = now.hour % 12 or 12
    clock = f"{h} {now.strftime('%p')}" if now.minute == 0 else f"{h} {now.minute:02d} {now.strftime('%p')}"
    parts = [f"{CFG.get('greeting', 'Good morning')}.",
             f"It is {clock}, {now.strftime('%A')}, {now.strftime('%B')} {ordinal(now.day)}.",
             "Network status report."]

    devs = st["devices"]
    on = [d for d in devs if d["online"]]
    parts.append(f"{plural(len(on), 'device')} online.")

    day_ago = time.time() - 86400
    recent = [e for e in st["events"] if e["t"] > day_ago]
    new_devs = [e for e in recent if e["kind"] == "new_device"]
    if new_devs:
        by_mac = {d["mac"]: d for d in devs}
        names = [by_mac.get(e["mac"], {}).get("label", "unknown device") for e in new_devs[:3]]
        more = f", and {len(new_devs) - 3} more" if len(new_devs) > 3 else ""
        parts.append(f"{plural(len(new_devs), 'new device')} joined overnight: {', '.join(n.rstrip('.') for n in names)}{more}.")
    else:
        parts.append("No new devices joined overnight.")

    threats = [e for e in recent if e["sev"] in ("warn", "crit") and e["kind"] != "new_device"]
    crit = [e for e in recent if e["sev"] == "crit"]
    if crit:
        parts.append(f"Warning. {plural(len(crit), 'critical alert')} in the last 24 hours. Most recent: {crit[0]['msg'].split(':')[0].split(' (')[0].rstrip('.')}.")
    elif threats:
        parts.append(f"{plural(len(threats), 'security warning')} in the last 24 hours. Check the dashboard.")
    else:
        parts.append("No threats detected.")

    watched = [s for s in st["servers"] if s.get("alerts")]
    pool = watched or st["servers"]
    down = [s for s in pool if not s["up"]]
    if not pool:
        parts.append("No home servers detected.")
    elif down:
        parts.append(f"{plural(len(down), 'server')} offline: {', '.join(s['name'].rstrip('.') for s in down)}.")
    else:
        parts.append(f"All {plural(len(pool), 'server')} online.")

    temp = st.get("pi", {}).get("temp_c")
    if temp is not None:
        parts.append(f"System temperature {round(temp)} degrees.")
    parts.append("End of report.")
    return " ".join(parts)


def speak(text):
    env = dict(os.environ)
    env.setdefault("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    cmd = ["espeak-ng", "-v", CFG.get("voice", "en-us+m3"), "-s", str(CFG.get("voice_speed", 145)),
           "-p", str(CFG.get("voice_pitch", 25)), text]
    try:
        subprocess.run(cmd, env=env, timeout=300)
    except FileNotFoundError:
        print("espeak-ng not installed")


def main():
    try:
        st = api("/api/status")
    except OSError as e:
        text = "Good morning. Network monitor is not responding. Please check the dashboard service."
        print("status unavailable:", e)
    else:
        text = compose(st)
    print(text)
    if "--print" in sys.argv:
        return
    try:
        api("/api/wake", post=True)
        time.sleep(3)  # give the screen a moment to switch to the dashboard
    except OSError:
        pass
    speak(text)


if __name__ == "__main__":
    main()
