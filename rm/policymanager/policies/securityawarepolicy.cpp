#include "securityawarepolicy.h"
#include <vector>
#include <algorithm>
#include <sstream>

namespace rp {

SecurityAwarePolicy::SecurityAwarePolicy(const AppMappingSet &apps, PlatformDescription pd) :
    apps_(apps),
    platformDescription_(pd),
    appsOnPu_(pd.getNumProcessingUnits(), 0)
{
}

static bool increaseCPUquota(AppMappingPtr appMapping, float scalePercentage)
{
    rmcommon::NumericValue curBand = appMapping->getCpuMax();
    if (curBand.isMax()) {
        return false;
    } else {
        int maxBand = appMapping->countPUs() * 100;
        if (curBand >= maxBand) {
            return false;
        } else {
            int newBand = curBand * (1 + scalePercentage);
            newBand = std::min(newBand, maxBand);
            appMapping->setCpuMax(newBand);
            return true;
        }
    }
}

static bool decreaseCPUquota(AppMappingPtr appMapping, float scalePercentage)
{
    rmcommon::NumericValue curBand = appMapping->getCpuMax();
    int numPUs = appMapping->countPUs();
    if (curBand.isMax())
        curBand = numPUs * 100;
    int minBand = (numPUs - 1) * 100;
    if (curBand <= minBand || curBand <= 0) {
        return false;
    } else {
        int newBand = curBand * (1 - scalePercentage);
        newBand = std::max(newBand, minBand);
        appMapping->setCpuMax(newBand);
        return true;
    }
}

void SecurityAwarePolicy::addApp(AppMappingPtr appMapping)
{
    pid_t pid = appMapping->getPid();
    try {
        auto level = appMapping->getSecurityLevel();
        int cpuMax = 100;
        rmcommon::NumericValue pidsMax = rmcommon::NumericValue(16);
        int initialPU = 0;

        switch (level) {
        case rmcommon::App::SecurityLevel::UNCLASSIFIED:
            cpuMax = 100;
            pidsMax = rmcommon::NumericValue(16);
            break;
        case rmcommon::App::SecurityLevel::LOW:
            cpuMax = 80;
            pidsMax = rmcommon::NumericValue(16);
            break;
        case rmcommon::App::SecurityLevel::MEDIUM:
            cpuMax = 100;
            pidsMax = rmcommon::NumericValue(32);
            break;
        case rmcommon::App::SecurityLevel::HIGH:
            cpuMax = 150;
            pidsMax = rmcommon::NumericValue(64);
            break;
        case rmcommon::App::SecurityLevel::CRITICAL:
            cpuMax = -1; // max
            pidsMax = rmcommon::NumericValue("max");
            break;
        }

        appMapping->setPuVector({{initialPU, initialPU}});
        ++appsOnPu_[initialPU];
        if (cpuMax > 0) {
            appMapping->setCpuMax(cpuMax);
        } else {
            appMapping->setCpuMax(rmcommon::NumericValue("max"));
        }
        appMapping->setBaselinePids(appMapping->getCurrentPids());

        std::ostringstream cpuOs, pidsOs;
        cpuOs << appMapping->getCpuMax();
        pidsOs << pidsMax;
        log4cpp::Category::getRoot().info("SECURITYAWAREPOLICY addApp PID %ld level=%d PU=%d cpu.max=%s pids.max=%s",
                                          (long)pid, (int)level, initialPU,
                                          cpuOs.str().c_str(),
                                          pidsOs.str().c_str());
    } catch (std::exception &e) {
        log4cpp::Category::getRoot().error("SECURITYAWAREPOLICY addApp PID %ld: EXCEPTION %s",
                                           (long)pid, e.what());
    }
}

void SecurityAwarePolicy::removeApp(AppMappingPtr appMapping)
{
    rmcommon::CpusetVector vec = appMapping->getPuVector();
    std::vector<short> vecPu = rmcommon::toVector(vec);
    for (short pu: vecPu) {
        --appsOnPu_[pu];
        appsOnPu_[pu] = std::max(appsOnPu_[pu], 0);
    }
}

void SecurityAwarePolicy::timer()
{
    // no action required
}

void SecurityAwarePolicy::monitor(std::shared_ptr<const rmcommon::MonitorEvent> event)
{
    lastPlatformLoad_ = event->getPlatformLoad();
}

void SecurityAwarePolicy::feedback(AppMappingPtr appMapping, int feedback)
{
    if (appMapping->isQuarantine()) {
        return;
    }

    float lowerLimit = 100.0f * 0.8f;
    float upperLimit = 100.0f * 1.2f;
    float scalePercentage = 0.15f;

    if (feedback < lowerLimit) {
        if (increaseCPUquota(appMapping, scalePercentage))
            return;
        // For HIGH/CRITICAL, try to add a PU
        auto level = appMapping->getSecurityLevel();
        if (level == rmcommon::App::SecurityLevel::HIGH || level == rmcommon::App::SecurityLevel::CRITICAL) {
            rmcommon::CpusetVector vec = appMapping->getPuVector();
            // Simple: just expand to PU 1 if currently on PU 0
            if (rmcommon::countPUs(vec) == 1) {
                rmcommon::addPU(vec, 1);
                appMapping->setPuVector(vec);
                ++appsOnPu_[1];
                increaseCPUquota(appMapping, scalePercentage);
            }
        }
    } else if (feedback > upperLimit) {
        if (decreaseCPUquota(appMapping, scalePercentage))
            return;
    }
    appMapping->setLastFeedback(feedback);
}

void SecurityAwarePolicy::securityAlert(AppMappingPtr appMapping, float sai,
                                        const sec::SecurityFactors &factors,
                                        const std::string &labels)
{
    // Phase 3: record the SAI and log. The graduated state-machine response
    // (throttle/restrict/freeze + recovery + contention) is implemented in
    // Phase 5; this keeps the new event/type contract wired end-to-end.
    (void)factors;
    pid_t pid = appMapping->getPid();
    appMapping->setSai(sai);
    log4cpp::Category::getRoot().info(
        "SECURITYAWAREPOLICY alert PID %ld: sai=%.3f labels=%s",
        (long)pid, sai, labels.c_str());
}

}   // namespace rp
