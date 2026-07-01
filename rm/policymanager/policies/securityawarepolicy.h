#ifndef SECURITYAWAREPOLICY_H
#define SECURITYAWAREPOLICY_H

#include "ibasepolicy.h"
#include "secstate.h"
#include <map>
#include <sys/types.h>

namespace rp {

class SecurityAwarePolicy : public IBasePolicy {
    const AppMappingSet &apps_;
    PlatformDescription platformDescription_;
    rmcommon::PlatformLoad lastPlatformLoad_;
    std::vector<int> appsOnPu_;
    PolicyThresholds thresholds_;
    /*! PU each app was originally pinned to in addApp; used to restore
        isolation when recovering to OBSERVE. */
    std::map<pid_t, int> assignedPu_;

    /*! Threshold offset added per security level (gentler containment for
        higher levels; availability-first). */
    float tolOffset(rmcommon::App::SecurityLevel level) const;
    /*! THROTTLE cpu.max fraction per security level. */
    float stepFactor(rmcommon::App::SecurityLevel level) const;
    /*! Applies the cgroup actions for a containment state (idempotent). */
    void applyState(AppMappingPtr appMapping, SecState state);

public:
    SecurityAwarePolicy(const AppMappingSet &apps, PlatformDescription pd);

    virtual const char *name() override {
        return "SecurityAwarePolicy";
    }
    virtual void addApp(AppMappingPtr appMapping) override;
    virtual void removeApp(AppMappingPtr appMapping) override;
    virtual void timer() override;
    virtual void monitor(std::shared_ptr<const rmcommon::MonitorEvent> event) override;
    virtual void feedback(AppMappingPtr appMapping, int feedback) override;
    virtual void securityAlert(AppMappingPtr appMapping, float sai,
                               const sec::SecurityFactors &factors,
                               const std::string &labels) override;

    /*! Operator action (via HTTP /clear): thaw + reset a quarantined app. */
    virtual void clearApp(AppMappingPtr appMapping) override;

    /*! Update escalation thresholds post-construction (called from KonroManager
     *  after reading the [securitypolicy] config section). */
    virtual void setThresholds(const PolicyThresholds &th) override;
};

}   // namespace rp

#endif // SECURITYAWAREPOLICY_H
