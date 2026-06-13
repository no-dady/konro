#include "securitymonitor.h"
#include "threadname.h"
#include "securityevent.h"
#include "addevent.h"
#include "removeevent.h"
#include "cgroupcontrol.h"
#include "pidscontrol.h"
#include <chrono>
#include <thread>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <set>

using namespace std;

namespace {

const vector<pair<string, string>> THREAT_PATTERNS = {
    {"telnetd", "telnetd"},
    {"merlinAgent", "merlinAgent"},
    {"hping3", "hping3"},
    {"ncat", "ncat"},
    {"nmap", "nmap"},
    {"busybox sh", "busybox_sh"},
};

} // anonymous namespace

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

string SecurityMonitor::getProcessCmdline(pid_t pid)
{
    ostringstream os;
    os << "/proc/" << pid << "/cmdline";
    fstream fs(os.str());
    string cmdline;
    if (fs.is_open()) {
        if (getline(fs, cmdline)) {
            replace(cmdline.begin(), cmdline.end(), '\0', ' ');
        }
    }
    return cmdline;
}

bool SecurityMonitor::isThreat(const string &cmdline, string &threatName)
{
    for (const auto &pattern : THREAT_PATTERNS) {
        if (cmdline.find(pattern.first) != string::npos) {
            threatName = pattern.second;
            return true;
        }
    }
    return false;
}

int SecurityMonitor::computeAnomalyScore(shared_ptr<rmcommon::App> app,
                                          const vector<pid_t> &pids,
                                          const vector<string> &threats)
{
    int baselinePids = app->getSecurityLevel() == rmcommon::App::SecurityLevel::CRITICAL ? 8 :
                       app->getSecurityLevel() == rmcommon::App::SecurityLevel::HIGH ? 6 :
                       app->getSecurityLevel() == rmcommon::App::SecurityLevel::MEDIUM ? 4 : 2;

    int currentPids = static_cast<int>(pids.size());
    int score = min(50 * currentPids / max(baselinePids, 1), 100);

    for (size_t i = 0; i < threats.size(); ++i) {
        score += 50;
    }

    return min(score, 200);
}

void SecurityMonitor::scanApp(shared_ptr<rmcommon::App> app)
{
    vector<pid_t> pids = getCgroupPids(app);
    vector<string> threats;

    for (pid_t pid : pids) {
        string cmdline = getProcessCmdline(pid);
        string threatName;
        if (isThreat(cmdline, threatName)) {
            threats.push_back(threatName);
            cat_.warn("SECURITYMONITOR threat detected in pid %ld: %s (cmdline: %s)",
                      (long)pid, threatName.c_str(), cmdline.c_str());
        }
    }

    int anomalyScore = computeAnomalyScore(app, pids, threats);
    if (anomalyScore >= 50) {
        ostringstream threatsOs;
        for (size_t i = 0; i < threats.size(); ++i) {
            if (i > 0) threatsOs << ",";
            threatsOs << threats[i];
        }
        // Phase 3 bridge: map the legacy 0-200 score onto SAI [0,1] with an
        // empty factor breakdown. Phase 4 replaces this with real per-cgroup
        // factor sampling.
        float sai = anomalyScore / 200.0f;
        cat_.info("SECURITYMONITOR publishing SecurityEvent for pid %ld, sai=%.3f, threats=%s",
                  (long)app->getPid(), sai, threatsOs.str().c_str());
        rmcommon::SecurityEvent *event = new rmcommon::SecurityEvent(app, sai, sec::SecurityFactors{}, threatsOs.str());
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
