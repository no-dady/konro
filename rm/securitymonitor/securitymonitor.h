#ifndef SECURITYMONITOR_H
#define SECURITYMONITOR_H

#include "eventbus.h"
#include "basethread.h"
#include "app.h"
#include "addevent.h"
#include "removeevent.h"
#include <log4cpp/Category.hh>
#include <memory>
#include <set>
#include <mutex>

/*!
 * \class periodically scans managed applications for security anomalies.
 * When unexpected processes are detected (e.g., telnetd, merlinAgent),
 * a SecurityEvent is published to the EventBus.
 */
class SecurityMonitor : public rmcommon::BaseThread {
    log4cpp::Category &cat_;
    int securityPeriod_;
    rmcommon::EventBus &bus_;

    std::set<std::shared_ptr<rmcommon::App>> apps_;
    std::mutex appsMutex_;

    void scanApp(std::shared_ptr<rmcommon::App> app);
    int computeAnomalyScore(std::shared_ptr<rmcommon::App> app,
                            const std::vector<pid_t> &pids,
                            const std::vector<std::string> &threats);
    std::vector<pid_t> getCgroupPids(std::shared_ptr<rmcommon::App> app);
    std::string getProcessCmdline(pid_t pid);
    bool isThreat(const std::string &cmdline, std::string &threatName);

    virtual void run() override;

public:
    SecurityMonitor(rmcommon::EventBus &bus, int securityPeriod);
    ~SecurityMonitor();

    void processAddEvent(std::shared_ptr<const rmcommon::AddEvent> event);
    void processRemoveEvent(std::shared_ptr<const rmcommon::RemoveEvent> event);
};

#endif // SECURITYMONITOR_H
