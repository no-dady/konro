#ifndef SECURITYAWAREPOLICY_H
#define SECURITYAWAREPOLICY_H

#include "ibasepolicy.h"

namespace rp {

class SecurityAwarePolicy : public IBasePolicy {
    const AppMappingSet &apps_;
    PlatformDescription platformDescription_;
    rmcommon::PlatformLoad lastPlatformLoad_;
    std::vector<int> appsOnPu_;

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
};

}   // namespace rp

#endif // SECURITYAWAREPOLICY_H
