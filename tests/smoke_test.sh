#!/usr/bin/env bash
# End-to-end smoke test with fake network tools. No real scanning happens.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'kill "${PID:-0}" 2>/dev/null || true; rm -rf "$WORK"' EXIT

cp -r "$ROOT/monitor.py" "$ROOT/briefing.py" "$ROOT/static" "$WORK/"
python3 - "$ROOT/config.json" "$WORK/config.json" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
c.update(port=8099, scan_interval_sec=2, quiet_hours=[0, 0])
json.dump(c, open(sys.argv[2], "w"))
PY
# start port scans after 3 s instead of 45 s
sed -i 's/\* 60, 45)/* 60, 3)/' "$WORK/monitor.py"

export PATH="$ROOT/tests/fakebin:$PATH" PIDASH_EXTRA="$WORK/extra.txt" PIDASH_SPOKEN="$WORK/spoken.txt"
python3 "$WORK/monitor.py" > "$WORK/monitor.log" 2>&1 &
PID=$!

fail() { echo "FAIL: $*"; echo "--- monitor log"; cat "$WORK/monitor.log"; exit 1; }
status() { curl -fsS http://127.0.0.1:8099/api/status; }

for _ in $(seq 20); do status >/dev/null 2>&1 && break; sleep 0.5; done
status >/dev/null || fail "dashboard did not start"
sleep 3

# 1. baseline devices are trusted
status | python3 -c 'import json,sys; s=json.load(sys.stdin); d=[x for x in s["devices"] if x["ip"].startswith("192.168.1.")]; assert len(d)==3 and all(x["trusted"] for x in d), d' \
  || fail "baseline not recorded"
echo "ok  baseline recorded"

# 2. a new device and a spoofed router raise alerts, each only once
printf '192.168.1.99\t56:7c:09:00:00:04\t(Unknown: locally administered)\n192.168.1.1\taa:bb:cc:00:00:05\tEvil\n' > "$WORK/extra.txt"
sleep 7
status | python3 -c '
import json,sys
s=json.load(sys.stdin); kinds=[e["kind"] for e in s["events"]]
assert "new_device" in kinds, kinds
assert kinds.count("ip_conflict")==1, kinds
assert "risky_port" in kinds, kinds
' || fail "alerts missing or repeated"
echo "ok  new device, spoofing (once), and risky port alerts"
grep -q "New device joined" "$WORK/spoken.txt" || fail "alert was not spoken"
echo "ok  alerts spoken"

# 3. hardening
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
[ "$(code -X POST -d x=1 http://127.0.0.1:8099/api/read)" = 415 ] || fail "form post not rejected"
[ "$(code -X POST -H 'Content-Type: application/json' -d '{}' http://127.0.0.1:8099/api/read)" = 200 ] || fail "json post rejected"
[ "$(code --path-as-is http://127.0.0.1:8099/../monitor.py)" = 404 ] || fail "path traversal not blocked"
curl -s -D - -o /dev/null http://127.0.0.1:8099/ | grep -qi '^x-frame-options: DENY' || fail "security headers missing"
echo "ok  hardening"

# 4. renaming works and label is escaped-safe JSON
curl -fsS -X POST -H 'Content-Type: application/json' -d '{"mac":"b8:97:5a:00:00:02","label":"<b>Desktop</b>","watch":true}' http://127.0.0.1:8099/api/device >/dev/null
status | grep -q '<b>Desktop</b>' || fail "rename failed"
echo "ok  rename"

# 5. morning briefing text
sed -i 's/8080/8099/' "$WORK/briefing.py"
out="$(python3 "$WORK/briefing.py" --print)"
echo "$out" | grep -q "Network status report" || fail "briefing text: $out"
echo "ok  briefing: $out"
echo "ALL SMOKE TESTS PASSED"
