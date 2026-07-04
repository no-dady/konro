#!/bin/bash
# Drives the Konro-vs-Mirai experiment inside the container and prints the
# konro log, a cgroup-state timeline and an overhead summary for offline
# analysis. SCENARIO (env) selects the victim behaviour: ramp|burst|recover|benign.
LOG=/var/log/konro.log
SCENARIO="${SCENARIO:-ramp}"

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

stdbuf -oL -eL /usr/local/bin/konro --config /etc/konro.ini --loglevel INFO > "$LOG" 2>&1 &
KONRO_PID=$!
sleep 3

SCENARIO="$SCENARIO" python3 /victim.py &
VPID=$!
echo "SCENARIO=$SCENARIO VICTIM_PID=$VPID KONRO_PID=$KONRO_PID"
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

# observation window depends on the scenario; recover needs time for the
# malicious phase AND the subsequent dwell-based recovery to complete.
case "$SCENARIO" in
    recover) DUR=105 ;;
    benign)  DUR=45  ;;
    *)       DUR=60  ;;
esac

# state + overhead timeline (overhead = konro's own RSS / CPU%, sampled here)
echo "=== TIMELINE (every 10s; overhead = konro process) ==="
n=$((DUR/10))
for i in $(seq 1 "$n"); do
    sleep 10
    ov=$(ps -o %cpu=,rss= -p "$KONRO_PID" 2>/dev/null | awk '{printf "cpu=%s%% rss=%dKiB",$1,$2}')
    echo "[t+$((i*10))s] konro $ov"
    dump_state
done

echo "=== STATE AFTER OBSERVATION ($SCENARIO) ==="
dump_state

if [ "$SCENARIO" = "burst" ]; then
    echo "=== POST /clear (operator recovery) ==="
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
fi

echo "=== STATE TRANSITIONS (policy) ==="
grep -E "SECURITYAWAREPOLICY PID .* [0-9]->[0-9]|QUARANTINE|RESTRICT|THROTTLE|cleared" "$LOG" || echo "  (none)"

if [ "$SCENARIO" = "benign" ]; then
    echo "=== FALSE-POSITIVE CHECK ==="
    if grep -qE "SECURITYAWAREPOLICY PID .* 0->[123]" "$LOG"; then
        echo "  FAIL: benign workload triggered a containment escalation"
    else
        echo "  PASS: benign workload stayed in OBSERVE (no escalation)"
    fi
fi

if [ "$SCENARIO" = "recover" ]; then
    echo "=== AUTO-RECOVERY CHECK ==="
    if grep -qE "SECURITYAWAREPOLICY PID .* [123]->0" "$LOG"; then
        echo "  PASS: app auto-recovered to OBSERVE after returning to benign"
    else
        echo "  (no return-to-OBSERVE transition found in log)"
    fi
fi

echo "=== KONRO LOG ==="
cat "$LOG"
