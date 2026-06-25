#!/usr/bin/env python3
"""Emulated IoT node that becomes Mirai-like after a baseline period.

Phases (by elapsed time since start):
  0-25s   normal   : idle sensor, no scanning
  25-40s  scanning : many half-open outbound connections to random IPs:23
  40s+    compromised: scanning + spawns a new binary + CPU burn
The process stays in Konro's cgroup, so SecurityMonitor observes the
behaviour via /proc/net and cgroup counters and the policy reacts.
"""
import os, socket, time, random, subprocess, threading, shutil

START = time.time()
SCENARIO = os.environ.get("SCENARIO", "ramp")   # "ramp" or "burst"
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


while True:
    el = time.time() - START
    if el < 22:
        time.sleep(2)                       # baseline / warmup
    elif SCENARIO == "burst":
        go_full()                           # straight to full compromise
        time.sleep(2)
    elif el < 40:
        scan(120)                           # ramp: scanning only
        time.sleep(2)
    else:
        go_full()                           # ramp: then full compromise
        time.sleep(2)
