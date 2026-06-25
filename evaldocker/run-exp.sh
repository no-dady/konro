#!/bin/bash
# Drives the Konro-vs-Mirai experiment inside the container and prints
# the konro log + final cgroup state for offline analysis.
LOG=/var/log/konro.log

# cgroup v2 delegation: cgroup v2 forbids enabling domain controllers on a
# cgroup that has member processes ("no internal processes"). Move our own
# processes into a leaf cgroup, then enable controllers at the root so Konro
# can set cpu.max/pids.max/memory.max on the cgroups it creates.
CG=/sys/fs/cgroup
mkdir -p "$CG/init.scope"
for p in $(cat "$CG/cgroup.procs" 2>/dev/null); do
    echo "$p" > "$CG/init.scope/cgroup.procs" 2>/dev/null || true
done
echo "+cpu +pids +memory" > "$CG/cgroup.subtree_control" 2>/dev/null || true
echo "ROOT subtree_control: $(cat "$CG/cgroup.subtree_control" 2>/dev/null)"

/usr/local/bin/konro --config /etc/konro.ini --loglevel INFO > "$LOG" 2>&1 &
sleep 3

python3 /victim.py &
VPID=$!
echo "VICTIM_PID=$VPID"
echo "VICTIM_START_EPOCH=$(date +%s)"

# register the victim with Konro (security service level LOW)
python3 - "$VPID" <<'PY'
import sys, json, urllib.request
pid = int(sys.argv[1])
data = json.dumps({"pid": pid, "type": "STANDALONE",
                   "name": "victim", "securityLevel": "LOW"}).encode()
req = urllib.request.Request("http://localhost:8080/add", data=data,
                             headers={"Content-Type": "application/json"})
print("ADD:", urllib.request.urlopen(req, timeout=5).read().decode().strip())
PY

dump_state() {
    for f in $(find /sys/fs/cgroup -path '*konro.slice/app-*' \( -name cpu.max -o -name cgroup.freeze -o -name pids.max \) 2>/dev/null); do
        echo "  $f = $(cat "$f" 2>/dev/null | tr '\n' ' ')"
    done
}

# baseline -> attack; watch a while
sleep 60

echo "=== STATE AFTER ATTACK ==="
dump_state

# operator recovery: thaw + reset via /clear
echo "=== POST /clear ==="
python3 - "$VPID" <<'PY'
import sys, json, urllib.request
pid = int(sys.argv[1])
data = json.dumps({"pid": pid}).encode()
req = urllib.request.Request("http://localhost:8080/clear", data=data,
                             headers={"Content-Type": "application/json"})
print("CLEAR:", urllib.request.urlopen(req, timeout=5).read().decode().strip())
PY
sleep 4
echo "=== STATE AFTER /clear ==="
dump_state

echo "=== KONRO LOG ==="
cat "$LOG"
