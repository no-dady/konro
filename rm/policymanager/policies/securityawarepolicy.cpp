#include "securityawarepolicy.h"
#include "../cgroupcontrol.h"
#include <vector>
#include <algorithm>
#include <sstream>

namespace rp {

float SecurityAwarePolicy::tolOffset(rmcommon::App::SecurityLevel level) const
{
    switch (level) {
    case rmcommon::App::SecurityLevel::MEDIUM:   return 0.05f;
    case rmcommon::App::SecurityLevel::HIGH:     return 0.10f;
    case rmcommon::App::SecurityLevel::CRITICAL: return 0.15f;
    default:                                     return 0.0f;  // UNCLASSIFIED/LOW
    }
}

float SecurityAwarePolicy::stepFactor(rmcommon::App::SecurityLevel level) const
{
    switch (level) {
    case rmcommon::App::SecurityLevel::HIGH:
    case rmcommon::App::SecurityLevel::CRITICAL: return 0.80f;
    case rmcommon::App::SecurityLevel::MEDIUM:   return 0.65f;
    default:                                     return 0.50f;  // UNCLASSIFIED/LOW
    }
}

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

        // The security level governs security treatment, not the resource
        // quota: every app starts with full cpu. HIGH/CRITICAL additionally
        // get a dedicated (least-loaded) PU for isolation; others share PU 0.
        bool isolate = (level == rmcommon::App::SecurityLevel::HIGH ||
                        level == rmcommon::App::SecurityLevel::CRITICAL);
        int pu = 0;
        if (isolate && !appsOnPu_.empty()) {
            pu = static_cast<int>(
                std::min_element(appsOnPu_.begin(), appsOnPu_.end()) - appsOnPu_.begin());
        }

        appMapping->setPuVector({{static_cast<short>(pu), static_cast<short>(pu)}});
        ++appsOnPu_[pu];
        assignedPu_[pid] = pu;          // remember for OBSERVE restore (FIX 1.3)
        appMapping->setCpuMax(rmcommon::NumericValue("max"));
        appMapping->setBaselinePids(appMapping->getCurrentPids());

        log4cpp::Category::getRoot().info(
            "SECURITYAWAREPOLICY addApp PID %ld level=%d PU=%d isolated=%d",
            (long)pid, (int)level, pu, (int)isolate);
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
    assignedPu_.erase(appMapping->getPid());
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

void SecurityAwarePolicy::applyState(AppMappingPtr appMapping, SecState state)
{
    auto &cat = log4cpp::Category::getRoot();
    pid_t pid = appMapping->getPid();
    auto level = appMapping->getSecurityLevel();
    int numPUs = platformDescription_.getNumProcessingUnits();

    switch (state) {
    case SecState::OBSERVE: {
        // restore full cpu allocation (idempotent) and the app's ORIGINAL
        // assigned PU, not all cores: spreading the app across {0..numPUs-1}
        // would destroy the per-app isolation addApp established.
        appMapping->setQuarantine(false);
        appMapping->setCpuMax(rmcommon::NumericValue("max"));
        if (numPUs > 0) {
            auto it = assignedPu_.find(pid);
            int pu = (it != assignedPu_.end()) ? it->second : 0;
            appMapping->setPuVector({{static_cast<short>(pu), static_cast<short>(pu)}});
        }
        break;
    }
    case SecState::THROTTLE: {
        int full = std::max(numPUs, 1) * 100;
        int band = std::max(static_cast<int>(full * stepFactor(level)), 10);
        appMapping->setCpuMax(band);
        cat.warn("SECURITYAWAREPOLICY THROTTLE PID %ld cpu.max=%d%%", (long)pid, band);
        break;
    }
    case SecState::RESTRICT: {
        appMapping->setCpuMax(20);
        appMapping->setPuVector({{0, 0}});
        // Clamp pids.max to the CLEAN baseline captured at addApp, not the
        // current task count: if the malware has already forked, getCurrentPids()
        // would lock in the compromised count and defeat the containment.
        int baselinePids = appMapping->getBaselinePids();
        int pidsCap = baselinePids > 0 ? baselinePids
                                       : (appMapping->getCurrentPids() > 0
                                              ? appMapping->getCurrentPids()
                                              : 2);
        appMapping->setMaxPids(pidsCap);
        cat.warn("SECURITYAWAREPOLICY RESTRICT PID %ld cpu.max=20%% PU=0 pids=%d",
                 (long)pid, pidsCap);
        break;
    }
    case SecState::QUARANTINE:
        appMapping->setQuarantine(true);
        pc::CGroupControl().setFreeze(true, appMapping->getApp());
        if (level == rmcommon::App::SecurityLevel::CRITICAL)
            cat.error("SECURITYAWAREPOLICY OPERATOR ALERT: CRITICAL app PID %ld quarantined",
                      (long)pid);
        cat.error("SECURITYAWAREPOLICY QUARANTINE PID %ld frozen (cgroup.freeze=1)", (long)pid);
        break;
    }
}

void SecurityAwarePolicy::securityAlert(AppMappingPtr appMapping, float sai,
                                        const sec::SecurityFactors &factors,
                                        const std::string &labels)
{
    (void)factors;
    pid_t pid = appMapping->getPid();
    appMapping->setSai(sai);

    SecState prev = appMapping->secState().state();
    SecState ns = appMapping->secState().step(sai, thresholds_,
                                              tolOffset(appMapping->getSecurityLevel()));

    if (ns != prev) {
        log4cpp::Category::getRoot().info(
            "SECURITYAWAREPOLICY PID %ld %d->%d sai=%.3f labels=%s",
            (long)pid, (int)prev, (int)ns, sai, labels.c_str());
        applyState(appMapping, ns);
    }
}

void SecurityAwarePolicy::setThresholds(const PolicyThresholds &th)
{
    thresholds_ = th;
    log4cpp::Category::getRoot().info(
        "SECURITYAWAREPOLICY thresholds updated: t1=%.2f t2=%.2f t3=%.2f dwellN=%d",
        th.t1, th.t2, th.t3, th.dwellN);
}

void SecurityAwarePolicy::clearApp(AppMappingPtr appMapping)
{
    pid_t pid = appMapping->getPid();
    appMapping->secState().clear();
    pc::CGroupControl().setFreeze(false, appMapping->getApp());
    appMapping->setQuarantine(false);
    appMapping->setSai(0.0f);
    applyState(appMapping, SecState::OBSERVE);
    log4cpp::Category::getRoot().info("SECURITYAWAREPOLICY PID %ld cleared (thawed + reset)",
                                      (long)pid);
}

}   // namespace rp
