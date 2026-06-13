#ifndef APPMAPPING_H
#define APPMAPPING_H

#include <app.h>
#include <memory>
#include <set>
#include "cpucontrol.h"
#include "cpusetcontrol.h"
#include "numericvalue.h"
#include "memorycontrol.h"
#include "pidscontrol.h"
#include "policies/secstate.h"

#ifdef TIMING
#include <log4cpp/Category.hh>
#include "timer.h"
#endif

namespace rp {

/*!
 * \class encapsulates an application and adds information about
 * the resources it can use.
 * This class acts as a cache with respect to cgroup files. Whenever
 * a new value is written to a cgroup file, this class stores the value
 * in a variable. Subsequent reads to this value can access the variable
 * instead of reading the file.
 * The setter methods of this class can be used to simultaneosuly write
 * the desired value to a cgroup file and store it in a variable.
 */
class AppMapping {
    std::shared_ptr<rmcommon::App> app_;
    /*! Processing Units that can execute the app */
    rmcommon::CpusetVector puVec_;
    /*! maximum cpu bandwidth limit */
    rmcommon::NumericValue cpuMax_;
    /*! memory nodes that can be used by the app */
    rmcommon::CpusetVector memNodes_;
    /*! minimum amount of memory the app must always retain */
    int minMemory_;
    /*! memory usage hard limit for the app */
    int maxMemory_;
    /*! last feedback value received from the app */
    int lastFeedback_;
    rmcommon::App::SecurityLevel securityLevel_;
    float sai_;
    rp::StateTracker secState_;
    bool quarantine_;
    int baselinePids_;

public:
    AppMapping(std::shared_ptr<rmcommon::App> app) :
        app_(app),
        minMemory_(-1),
        maxMemory_(-1),
        lastFeedback_(-1),
        securityLevel_(app->getSecurityLevel()),
        sai_(0.0f),
        quarantine_(false),
        baselinePids_(-1)
    {
    }
    ~AppMapping() = default;

    /*!
     * \brief Gets the pid of the application
     * \returns the pid of the application
     */
    pid_t getPid() const {
        return app_->getPid();
    }

    std::shared_ptr<rmcommon::App> getApp() const {
        return app_;
    }

    const std::string getCgroupDir() const noexcept {
        return app_->getCgroupDir();
    }

    rmcommon::CpusetVector getPuVector() {
        if (puVec_.empty()) {
            puVec_ = pc::CpusetControl::instance().getCpusEffective(app_);
        }
        return puVec_;
    }

    void setPuVector(rmcommon::CpusetVector puVec) {
#ifdef TIMING
        rmcommon::KonroTimer timer;
#endif

        pc::CpusetControl::instance().setCpus(puVec, app_);

#ifdef TIMING
        rmcommon::KonroTimer::TimeUnit micros = timer.Elapsed();
        log4cpp::Category::getRoot().debug("APPMAPPING setPuVector timing: setCpus = %d microseconds",
                                           micros.count());
#endif
        puVec_ = puVec;
    }

    /*! Returns the number of PUs used */
    int countPUs() const {
        return rmcommon::countPUs(puVec_);
    }

    rmcommon::NumericValue getCpuMax() {
        if (cpuMax_.isInvalid()) {
            cpuMax_ = pc::CpuControl::instance().getMax(app_);
        }
        return cpuMax_;
    }

    void setCpuMax(rmcommon::NumericValue cpuMax) {
        pc::CpuControl::instance().setMax(cpuMax, app_);
        cpuMax_ = cpuMax;
    }

    rmcommon::CpusetVector getMemNodes() {
        if (memNodes_.empty()) {
            memNodes_ = pc::CpusetControl::instance().getMemsEffective(app_);
        }
        return memNodes_;
    }

    void setMemNodes(rmcommon::CpusetVector memNodes) {
        pc::CpusetControl::instance().setMems(memNodes, app_);
        memNodes_ = memNodes;
    }

    /*! total amount of memory currently used by the app */
    int getCurrentMemory() {
        return pc::MemoryControl::instance().getCurrent(app_);
    }

    int getMinMemory() {
        if (minMemory_ == -1) {
            minMemory_ = pc::MemoryControl::instance().getMin(app_);
        }
        return minMemory_;
    }

    void setMinMemory(int minMemory) {
        pc::MemoryControl::instance().setMin(minMemory, app_);
        minMemory_ = minMemory;
    }

    rmcommon::NumericValue getMaxMemory() {
        if (maxMemory_ == -1) {
            maxMemory_ = pc::MemoryControl::instance().getMax(app_);
        }
        return maxMemory_;
    }

    void setMaxMemory(rmcommon::NumericValue maxMemory) {
        pc::MemoryControl::instance().setMax(maxMemory, app_);
        maxMemory_ = maxMemory;
    }

    int getLastFeedback() {
        return lastFeedback_;
    }

    void setLastFeedback(int feedback) {
        lastFeedback_ = feedback;
    }

    rmcommon::App::SecurityLevel getSecurityLevel() const noexcept {
        return securityLevel_;
    }

    void setSecurityLevel(rmcommon::App::SecurityLevel level) {
        securityLevel_ = level;
    }

    float getSai() const noexcept {
        return sai_;
    }

    void setSai(float sai) {
        sai_ = sai;
    }

    /*! Per-app containment state machine (pure; advanced by the policy). */
    rp::StateTracker &secState() noexcept {
        return secState_;
    }

    bool isQuarantine() const noexcept {
        return quarantine_;
    }

    void setQuarantine(bool quarantine) {
        quarantine_ = quarantine;
    }

    int getBaselinePids() const noexcept {
        return baselinePids_;
    }

    void setBaselinePids(int pids) {
        baselinePids_ = pids;
    }

    int getCurrentPids() {
        return pc::PidsControl::instance().getCurrent(app_);
    }

    rmcommon::NumericValue getMaxPids() {
        return pc::PidsControl::instance().getMax(app_);
    }

    void setMaxPids(rmcommon::NumericValue maxPids) {
        pc::PidsControl::instance().setMax(maxPids, app_);
    }
};

using AppMappingPtr = std::shared_ptr<AppMapping>;

/*! Comparison function for the set */
using AppMappingComparator = bool (*)(const AppMappingPtr &lhs,
                                      const AppMappingPtr &rhs);

using AppMappingSet = std::set<AppMappingPtr, AppMappingComparator>;

}   // namespace rp

#endif // APPMAPPING_H
