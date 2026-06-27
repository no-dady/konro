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

    float sai = sec::computeSai(f, weights_);

    if (sai >= publishThreshold_) {
        if (f.fanout > 0.5f) labels << "fanout ";
        if (f.halfOpen > 0.5f) labels << "scan ";
        if (f.cpuBurst > 0.5f) labels << "cpu ";
        cat_.info("SECURITYMONITOR publishing SecurityEvent for pid %ld, sai=%.3f, dests=%d synSent=%d procs=%zu",
                  (long)pid, sai, distinctDests, synSent, pids.size());
        rmcommon::SecurityEvent *event = new rmcommon::SecurityEvent(app, sai, f, labels.str());
        bus_.publish(event);
    }
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
