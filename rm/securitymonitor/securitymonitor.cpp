#include "securitymonitor.h"
#include "threadname.h"
#include "securityevent.h"
#include "addevent.h"
#include "removeevent.h"
#include "cgroupcontrol.h"
#include <chrono>
#include <thread>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <dirent.h>
#include <unistd.h>

using namespace std;

SecurityMonitor::SecurityMonitor(rmcommon::EventBus &bus, int securityPeriod) :
    cat_(log4cpp::Category::getRoot()),
    securityPeriod_(securityPeriod),
    bus_(bus)
{
    bus_.subscribe<SecurityMonitor, rmcommon::AddEvent>(
        this, &SecurityMonitor::processAddEvent);
    bus_.subscribe<SecurityMonitor, rmcommon::RemoveEvent>(
        this, &SecurityMonitor::processRemoveEvent);
}

SecurityMonitor::~SecurityMonitor()
{
}

void SecurityMonitor::processAddEvent(std::shared_ptr<const rmcommon::AddEvent> event)
{
    auto app = event->getApp();
    lock_guard<mutex> lock(appsMutex_);
    apps_.insert(app);
    baselines_[app->getPid()];      // create empty baseline
    cat_.info("SECURITYMONITOR added app pid %ld", (long)app->getPid());
}

void SecurityMonitor::processRemoveEvent(std::shared_ptr<const rmcommon::RemoveEvent> event)
{
    auto app = event->getApp();
    lock_guard<mutex> lock(appsMutex_);
    auto it = find_if(apps_.begin(), apps_.end(),
                      [&app](const shared_ptr<rmcommon::App> &a) {
                          return a->getPid() == app->getPid();
                      });
    if (it != apps_.end()) {
        apps_.erase(it);
        baselines_.erase(app->getPid());
        cat_.info("SECURITYMONITOR removed app pid %ld", (long)app->getPid());
    }
}

vector<pid_t> SecurityMonitor::getCgroupPids(shared_ptr<rmcommon::App> app)
{
    vector<pid_t> pids;
    vector<string> lines = pc::CGroupControl().getContent("pids", "cgroup.procs", app);
    for (const string &line : lines) {
        if (!line.empty()) {
            pid_t pid = static_cast<pid_t>(strtol(line.c_str(), nullptr, 10));
            if (pid > 0) {
                pids.push_back(pid);
            }
        }
    }
    return pids;
}

map<ino_t, pid_t> SecurityMonitor::socketInodeToPid(const vector<pid_t> &pids)
{
    map<ino_t, pid_t> result;
    for (pid_t pid : pids) {
        ostringstream fdDir;
        fdDir << "/proc/" << pid << "/fd";
        DIR *d = opendir(fdDir.str().c_str());
        if (!d)
            continue;
        struct dirent *ent;
        while ((ent = readdir(d)) != nullptr) {
            ostringstream linkPath;
            linkPath << fdDir.str() << "/" << ent->d_name;
            char target[128];
            ssize_t n = readlink(linkPath.str().c_str(), target, sizeof(target) - 1);
            if (n <= 0)
                continue;
            target[n] = '\0';
            // links look like "socket:[12345]"
            if (strncmp(target, "socket:[", 8) == 0) {
                ino_t inode = static_cast<ino_t>(strtoul(target + 8, nullptr, 10));
                if (inode > 0)
                    result[inode] = pid;
            }
        }
        closedir(d);
    }
    return result;
}

void SecurityMonitor::countConnections(const set<ino_t> &inodes, pid_t netnsPid,
                                       int &distinctDests, int &synSent, int &total)
{
    distinctDests = 0;
    synSent = 0;
    total = 0;
    set<string> dests;
    // Read the connection table from the app's own network namespace
    // (/proc/<pid>/net), so this works whether Konro runs inside the app's
    // container or on the host managing a containerised app. Falls back to
    // the caller's namespace when no pid is available.
    string base = netnsPid > 0 ? ("/proc/" + to_string(netnsPid) + "/net/") : string("/proc/net/");
    const string files[] = { base + "tcp", base + "tcp6" };
    for (const string &file : files) {
        ifstream fs(file);
        if (!fs.is_open())
            continue;
        string line;
        getline(fs, line);          // skip header
        while (getline(fs, line)) {
            istringstream is(line);
            string sl, local, rem, st, txrx, trwhen, retr, uid, timeout, inodeStr;
            if (!(is >> sl >> local >> rem >> st >> txrx >> trwhen >> retr >> uid >> timeout >> inodeStr))
                continue;
            ino_t inode = static_cast<ino_t>(strtoul(inodeStr.c_str(), nullptr, 10));
            if (inodes.find(inode) == inodes.end())
                continue;
            ++total;
            if (st == "02")         // TCP_SYN_SENT
                ++synSent;
            string remIp = rem.substr(0, rem.find(':'));
            // ignore the all-zero remote address (listening / unconnected)
            if (remIp.find_first_not_of('0') != string::npos)
                dests.insert(remIp);
        }
    }
    distinctDests = static_cast<int>(dests.size());
}

bool SecurityMonitor::hasRawSockets(const set<ino_t> &inodes, pid_t netnsPid)
{
    if (inodes.empty())
        return false;
    string base = netnsPid > 0 ? ("/proc/" + to_string(netnsPid) + "/net/") : string("/proc/net/");

    // /proc/net/raw{,6}: sl local rem ... inode ref pointer drops   (inode = field 9)
    // /proc/net/packet:  sk RefCnt Type Proto Iface R Rmem User Inode  (inode = last field)
    auto indexOfInode = [&](const string &path, int idx) -> bool {
        ifstream fs(path);
        if (!fs.is_open())
            return false;
        string line;
        getline(fs, line);          // skip header
        while (getline(fs, line)) {
            istringstream is(line);
            string field;
            for (int i = 0; i <= idx; i++) {
                if (!(is >> field))
                    break;
                if (i == idx) {
                    ino_t inode = static_cast<ino_t>(strtoul(field.c_str(), nullptr, 10));
                    if (inode > 0 && inodes.find(inode) != inodes.end())
                        return true;
                }
            }
        }
        return false;
    };
    if (indexOfInode(base + "raw", 9))
        return true;
    if (indexOfInode(base + "raw6", 9))
        return true;
    // packet: inode is the last field — walk backwards
    {
        ifstream fs(base + "packet");
        if (fs.is_open()) {
            string line;
            getline(fs, line);
            while (getline(fs, line)) {
                istringstream is(line);
                string last;
                while (is >> last) { }
                ino_t inode = static_cast<ino_t>(strtoul(last.c_str(), nullptr, 10));
                if (inode > 0 && inodes.find(inode) != inodes.end())
                    return true;
            }
        }
    }
    return false;
}

string SecurityMonitor::getProcessComm(pid_t pid)
{
    ostringstream path;
    path << "/proc/" << pid << "/comm";
    ifstream fs(path.str());
    string comm;
    if (fs.is_open())
        getline(fs, comm);
    return comm;
}

uint64_t SecurityMonitor::getCpuUsec(shared_ptr<rmcommon::App> app)
{
    try {
        map<string, uint64_t> stat = pc::CGroupControl().getContentAsMap("cpu", "cpu.stat", app);
        auto it = stat.find("usage_usec");
        if (it != stat.end())
            return it->second;
    } catch (...) {
        // cpu.stat may be unavailable; treat as no sample
    }
    return 0;
}

uint64_t SecurityMonitor::getTxBytes(pid_t netnsPid)
{
    // Read transmitted bytes from the app's own network namespace, mirroring
    // countConnections (/proc/<pid>/net). Falls back to the caller's namespace
    // when no pid is available.
    string path = netnsPid > 0 ? ("/proc/" + to_string(netnsPid) + "/net/dev")
                                : string("/proc/net/dev");
    ifstream fs(path);
    if (!fs.is_open())
        return 0;
    uint64_t txTotal = 0;
    string line;
    // /proc/.../net/dev has two header lines before the per-interface rows.
    getline(fs, line);
    getline(fs, line);
    while (getline(fs, line)) {
        // Format: "iface: rxbytes rxpackets ... txbytes ..."
        // After the "iface:" label the columns are 8 rx fields followed by the
        // tx fields, so tx bytes is the 9th token after the label.
        size_t colon = line.find(':');
        if (colon == string::npos)
            continue;
        string iface = line.substr(0, colon);
        // trim leading/trailing whitespace from the interface name
        size_t b = iface.find_first_not_of(" \t");
        size_t e = iface.find_last_not_of(" \t");
        if (b == string::npos)
            continue;
        iface = iface.substr(b, e - b + 1);
        if (iface == "lo")
            continue;
        istringstream is(line.substr(colon + 1));
        uint64_t field = 0;
        bool ok = true;
        for (int i = 0; i < 9; ++i) {
            if (!(is >> field)) { ok = false; break; }
        }
        if (ok)
            txTotal += field;       // 9th field == tx bytes
    }
    return txTotal;
}

uint64_t SecurityMonitor::getMemCurrent(shared_ptr<rmcommon::App> app)
{
    try {
        // memory.current is a single bare integer (bytes); getLine returns the
        // raw value, parsed as 64-bit to avoid the truncation in getValueAsInt.
        string value = pc::CGroupControl().getLine("memory", "memory.current", app);
        return strtoull(value.c_str(), nullptr, 10);
    } catch (...) {
        // memory.current may be unavailable; treat as no sample
    }
    return 0;
}

void SecurityMonitor::scanApp(shared_ptr<rmcommon::App> app)
{
    pid_t pid = app->getPid();
    AppBaseline &base = baselines_[pid];

    vector<pid_t> pids = getCgroupPids(app);
    map<ino_t, pid_t> inodeMap = socketInodeToPid(pids);
    set<ino_t> inodes;
    for (const auto &kv : inodeMap)
        inodes.insert(kv.first);

    int distinctDests = 0, synSent = 0, total = 0;
    pid_t netnsPid = pids.empty() ? 0 : pids.front();
    countConnections(inodes, netnsPid, distinctDests, synSent, total);
    float halfOpenRatio = total > 0 ? static_cast<float>(synSent) / total : 0.0f;

    sec::SecurityFactors f;
    ostringstream labels;

    // A1/A2 network factors
    f.fanout = base.fanout.deviation(static_cast<float>(distinctDests));
    f.halfOpen = base.halfOpen.deviation(halfOpenRatio);
    base.fanout.update(static_cast<float>(distinctDests), alpha_);
    base.halfOpen.update(halfOpenRatio, alpha_);

    // A3 egress byte rate (network flood). Reuse the netnsPid already computed
    // for countConnections; read tx bytes from the app's net/dev.
    uint64_t txNow = getTxBytes(netnsPid);
    if (base.egressInit && securityPeriod_ > 0) {
        float rate = (txNow >= base.lastTxBytes)
                     ? static_cast<float>(txNow - base.lastTxBytes) / securityPeriod_
                     : 0.0f;        // counter wrap / interface reset -> no spike
        f.egress = base.egress.deviation(rate);
        base.egress.update(rate, alpha_);
    }
    base.lastTxBytes = txNow;
    base.egressInit = true;

    // B1 process count
    float procCount = static_cast<float>(pids.size());
    f.forkRate = base.forkRate.deviation(procCount);
    base.forkRate.update(procCount, alpha_);

    // B2 unexpected exec (discrete). Populate the known set during warmup
    // (reuse forkRate's warmup gate); after that, any new binary fires.
    bool warming = base.forkRate.warming();
    for (pid_t p : pids) {
        string comm = getProcessComm(p);
        if (comm.empty())
            continue;
        if (base.knownExecs.find(comm) == base.knownExecs.end()) {
            base.knownExecs.insert(comm);
            if (!warming) {
                f.newExec = 1.0f;
                labels << "exec:" << comm << " ";
            }
        }
    }

    // A4 raw/packet socket (discrete). Fires at most once per app lifetime.
    // Note: only mark fired when !warming so that a detection during warmup
    // does not suppress the real alert once the baseline period ends.
    if (hasRawSockets(inodes, netnsPid)) {
        if (!warming && !base.rawSocketFired) {
            base.rawSocketFired = true;
            f.rawSocket = 1.0f;
        }
    }

    // C1 cpu burst (rate of cgroup cpu usage between scans)
    uint64_t cpuNow = getCpuUsec(app);
    if (base.cpuInit && securityPeriod_ > 0) {
        float rate = (cpuNow >= base.lastCpuUsec)
                     ? static_cast<float>(cpuNow - base.lastCpuUsec) / securityPeriod_
                     : 0.0f;
        f.cpuBurst = base.cpuBurst.deviation(rate);
        base.cpuBurst.update(rate, alpha_);
    }
    base.lastCpuUsec = cpuNow;
    base.cpuInit = true;

    // D1 memory growth (memory exhaustion): rate of memory.current increase
    uint64_t memNow = getMemCurrent(app);
    if (base.memInit && securityPeriod_ > 0) {
        float rate = (memNow >= base.lastMemCurrent)
                     ? static_cast<float>(memNow - base.lastMemCurrent) / securityPeriod_
                     : 0.0f;        // freed memory is not an anomaly
        f.memGrowth = base.memGrowth.deviation(rate);
        base.memGrowth.update(rate, alpha_);
    }
    base.lastMemCurrent = memNow;
    base.memInit = true;

    float sai = sec::computeSai(f, weights_);

    // Publish a SecurityEvent EVERY period for EVERY managed app, regardless
    // of SAI. The policy's StateTracker owns all threshold logic (escalate
    // immediately, recover only after dwellN consecutive low-SAI periods), and
    // step() only runs on a published event. If we gated publishing on
    // publishThreshold_ (== t1), the low-SAI samples needed to recover from
    // THROTTLE back to OBSERVE would be silently dropped and the app would stay
    // clamped forever. So the gate is kept ONLY to suppress the verbose log
    // line on benign samples; the event itself always fires. A low-SAI event
    // with empty labels is correct and cheap (the period is measured in
    // seconds). See testsecuritypolicy::test_full_recovery_to_observe.
    if (f.fanout > 0.0f) labels << "fanout ";
    if (f.halfOpen > 0.0f) labels << "scan ";
    if (f.cpuBurst > 0.0f) labels << "cpu ";
    if (f.egress > 0.0f) labels << "egress ";
    if (f.memGrowth > 0.0f) labels << "mem ";
    if (f.rawSocket > 0.0f) labels << "rawsock ";

    if (sai >= publishThreshold_) {
        cat_.info("SECURITYMONITOR publishing SecurityEvent for pid %ld, sai=%.3f, dests=%d synSent=%d procs=%zu",
                  (long)pid, sai, distinctDests, synSent, pids.size());
    }
    rmcommon::SecurityEvent *event = new rmcommon::SecurityEvent(app, sai, f, labels.str());
    bus_.publish(event);
}

void SecurityMonitor::run()
{
    setThreadName("SECURITYMONITOR");
    cat_.info("SECURITYMONITOR running with period=%ds", securityPeriod_);

    while (!stopped()) {
        for (int i = 0; i < securityPeriod_ && !stopped(); ++i) {
            this_thread::sleep_for(chrono::seconds(1));
        }
        if (stopped())
            break;

        lock_guard<mutex> lock(appsMutex_);
        for (auto &app : apps_) {
            if (stopped())
                break;
            try {
                scanApp(app);
            } catch (exception &e) {
                cat_.error("SECURITYMONITOR exception scanning pid %ld: %s",
                           (long)app->getPid(), e.what());
            }
        }
    }

    cat_.info("SECURITYMONITOR exiting");
}
