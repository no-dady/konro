#ifndef SECURITYMONITOR_H
#define SECURITYMONITOR_H

#include "eventbus.h"
#include "basethread.h"
#include "app.h"
#include "sai.h"
#include "addevent.h"
#include "removeevent.h"
#include <log4cpp/Category.hh>
#include <memory>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <mutex>
#include <sys/types.h>

/*!
 * \class periodically samples each managed application's cgroup and
 * computes a composite Security Anomaly Index (SAI) from behavioural
 * factors compared to a per-app EWMA baseline. When the SAI exceeds a
 * threshold a SecurityEvent is published to the EventBus.
 */
class SecurityMonitor : public rmcommon::BaseThread {

    /*! Per-app baseline state kept across sampling periods. */
    struct AppBaseline {
        sec::Ewma fanout;
        sec::Ewma halfOpen;
        sec::Ewma forkRate;
        sec::Ewma cpuBurst;
        std::set<std::string> knownExecs;
        uint64_t lastCpuUsec = 0;
        bool cpuInit = false;
    };

    log4cpp::Category &cat_;
    int securityPeriod_;
    rmcommon::EventBus &bus_;
    sec::SaiWeights weights_;
    float alpha_ = 0.3f;
    float publishThreshold_ = 0.4f;

    std::set<std::shared_ptr<rmcommon::App>> apps_;
    std::map<pid_t, AppBaseline> baselines_;
    std::mutex appsMutex_;

    void scanApp(std::shared_ptr<rmcommon::App> app);

    std::vector<pid_t> getCgroupPids(std::shared_ptr<rmcommon::App> app);
    /*! Maps each socket inode owned by the given pids to its pid. */
    std::map<ino_t, pid_t> socketInodeToPid(const std::vector<pid_t> &pids);
    /*! Counts distinct remote destinations and SYN_SENT sockets among the
        connections whose inode belongs to the given set (from /proc/net/tcp{,6}). */
    void countConnections(const std::set<ino_t> &inodes,
                          int &distinctDests, int &synSent, int &total);

    virtual void run() override;

public:
    SecurityMonitor(rmcommon::EventBus &bus, int securityPeriod);
    ~SecurityMonitor();

    void processAddEvent(std::shared_ptr<const rmcommon::AddEvent> event);
    void processRemoveEvent(std::shared_ptr<const rmcommon::RemoveEvent> event);
};

#endif // SECURITYMONITOR_H
