#!/usr/bin/env python3
"""Emulated IoT node whose behaviour over time is set by $SCENARIO:

  ramp     baseline -> scan-only -> full compromise (stays malicious)
  burst    baseline -> full compromise in one step (stays malicious)
  recover  baseline -> full compromise -> returns to benign
           (exercises the policy's auto-recovery / hysteresis path)
  benign   never malicious (false-positive baseline)

The process stays in Konro's cgroup, so SecurityMonitor observes the
behaviour via /proc/net and the cgroup counters and the policy reacts.
"""
import os, socket, time, random, subprocess, threading, shutil

START = time.time()
SCENARIO = os.environ.get("SCENARIO", "ramp")
socks = []


def scan(n):
    for _ in range(n):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(False)
        ip = "%d.%d.%d.%d" % (random.randint(11, 223), random.randint(0, 255),
                              random.randint(0, 255), random.randint(1, 254))
        try:
            s.connect_ex((ip, 23))      # telnet; dead IPs stay SYN_SENT
        except OSError:
            pass
        socks.append(s)
    while len(socks) > 400:             # keep a bounded backlog of half-open
        try:
            socks.pop(0).close()
        except OSError:
            pass


def cpu_burn(stop):
    x = 0
    while not stop.is_set():
        x = (x * x + 1) % 2147483647


spawned = False
burn_stop = threading.Event()


def go_full():
    global spawned
    scan(150)
    if not spawned:
        try:
            shutil.copy("/bin/sleep", "/tmp/evilbot")
            subprocess.Popen(["/tmp/evilbot", "600"])
        except Exception:
            pass
        threading.Thread(target=cpu_burn, args=(burn_stop,), daemon=True).start()
        spawned = True


def go_benign():
    # Stop being malicious: end the CPU burn and drop every half-open socket so
    # the fan-out, half-open and CPU factors fall back below their EWMA
    # baselines. newExec already fired once and does not recur. With the
    # monitor publishing every period, the SAI decays and the policy's dwell
    # hysteresis steps the app back down to OBSERVE.
    burn_stop.set()
    while socks:
        try:
            socks.pop().close()
        except OSError:
            pass


while True:
    el = time.time() - START
    if SCENARIO == "benign":
        time.sleep(2)                       # idle sensor, never malicious
    elif el < 22:
        time.sleep(2)                       # baseline / warmup
    elif SCENARIO == "burst":
        go_full()
        time.sleep(2)
    elif SCENARIO == "recover":
        # Scan-only malicious window: enough to escalate to THROTTLE/RESTRICT
        # but below the QUARANTINE ceiling (which is sticky and manual-clear
        # only), so the auto-recovery / dwell path can be exercised.
        if el < 50:
            scan(120)                       # malicious window (no new exec / cpu burn)
        else:
            go_benign()                     # return to benign -> auto-recovery
        time.sleep(2)
    elif el < 40:
        scan(120)                           # ramp: scanning only
        time.sleep(2)
    else:
        go_full()                           # ramp: then full compromise
        time.sleep(2)
