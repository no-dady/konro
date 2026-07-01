#include "policymanager.h"
#include "policies/nopolicy.h"
#include "policies/randpolicy.h"
#include "policies/puprogressivepolicy.h"
#include "policies/mincorespolicy.h"
#include "policies/securityawarepolicy.h"
#include "threadname.h"
#include "eventbus.h"
#include "securityevent.h"
#include <iostream>
#include <sstream>
#include <thread>
#include <algorithm>

using namespace std;

namespace rp {

/*!
 * Compares two AppMapping ("less" function) handled
 * by shared pointers
 *
 * \param lhs the first app to compare
 * \param rhs the second app to compare
 * \return true if pid of lsh is < than pid of rhs
 */
static bool appMappingComp(const AppMappingPtr &lhs, const AppMappingPtr &rhs)
{
    return lhs->getPid() < rhs->getPid();
}

PolicyManager::PolicyManager(rmcommon::EventBus &bus, PlatformDescription pd, Policy policy) :
    rmcommon::BaseEventReceiver("POLICYMANAGER"),
    cat_(log4cpp::Category::getRoot()),
    bus_(bus),
    platformDescription_(pd),
    apps_(appMappingComp)
{
    subscribeToEvents();
    policy_ = makePolicy(policy);
}

std::unique_ptr<IBasePolicy> PolicyManager::makePolicy(Policy policy)
{
    switch (policy) {
    case Policy::RandPolicy:
        return make_unique<RandPolicy>(apps_, platformDescription_);
    case Policy::PuProgressivePolicy:
        return make_unique<PuProgressivePolicy>(apps_, platformDescription_);
    case Policy::MinCoresPolicy:
        return make_unique<MinCoresPolicy>(apps_, platformDescription_);
    case Policy::SecurityAwarePolicy:
        return make_unique<SecurityAwarePolicy>(apps_, platformDescription_);
    case Policy::NoPolicy:
    default:
        return make_unique<NoPolicy>();
        break;
    }
}

PolicyManager::Policy PolicyManager::getPolicyByName(const std::string &policyName)
{
    if (policyName == "RandPolicy")
        return Policy::RandPolicy;
    else if (policyName == "PuProgressivePolicy")
        return Policy::PuProgressivePolicy;
    else if (policyName == "MinCoresPolicy")
        return Policy::MinCoresPolicy;
    else if (policyName == "SecurityAwarePolicy")
        return Policy::SecurityAwarePolicy;
    else
        return Policy::NoPolicy;
}

void PolicyManager::subscribeToEvents()
{
    using namespace rmcommon;

    bus_.subscribe<PolicyManager, AddEvent, BaseEvent>(this, &PolicyManager::addEvent);
    bus_.subscribe<PolicyManager, RemoveEvent, BaseEvent>(this, &PolicyManager::addEvent);
    bus_.subscribe<PolicyManager, TimerEvent, BaseEvent>(this, &PolicyManager::addEvent);
    bus_.subscribe<PolicyManager, FeedbackEvent, BaseEvent>(this, &PolicyManager::addEvent);
    bus_.subscribe<PolicyManager, MonitorEvent, BaseEvent>(this, &PolicyManager::addEvent);
    bus_.subscribe<PolicyManager, SecurityEvent, BaseEvent>(this, &PolicyManager::addEvent);
    bus_.subscribe<PolicyManager, ClearEvent, BaseEvent>(this, &PolicyManager::addEvent);
}

bool PolicyManager::processEvent(std::shared_ptr<const rmcommon::BaseEvent> event)
{
    using namespace rmcommon;

#if 0
    ostringstream os;
    os << "POLICYMANAGER received message => " << *event;
    cat_.debug(os.str());
#endif
    if (const AddEvent *e = dynamic_cast<const AddEvent *>(event.get())) {
        processAddEvent(static_pointer_cast<const AddEvent>(event));
    } else if (const RemoveEvent *e = dynamic_cast<const RemoveEvent *>(event.get())) {
        processRemoveEvent(static_pointer_cast<const RemoveEvent>(event));
    } else if (const TimerEvent *e = dynamic_cast<const TimerEvent *>(event.get())) {
        processTimerEvent(static_pointer_cast<const TimerEvent>(event));
    } else if (const MonitorEvent *e = dynamic_cast<const MonitorEvent *>(event.get())) {
        processMonitorEvent(static_pointer_cast<const MonitorEvent>(event));
    } else if (const FeedbackEvent *e = dynamic_cast<const FeedbackEvent *>(event.get())) {
        processFeedbackEvent(static_pointer_cast<const FeedbackEvent>(event));
    } else if (const SecurityEvent *e = dynamic_cast<const SecurityEvent *>(event.get())) {
        processSecurityEvent(static_pointer_cast<const SecurityEvent>(event));
    } else if (const ClearEvent *e = dynamic_cast<const ClearEvent *>(event.get())) {
        processClearEvent(static_pointer_cast<const ClearEvent>(event));
    }
    return true;        // continue processing
}

void PolicyManager::processAddEvent(std::shared_ptr<const rmcommon::AddEvent> event)
{
    cat_.debug("POLICYMANAGER AddEvent received");
    AppMappingPtr appMapping = make_shared<AppMapping>(event->getApp());
    apps_.insert(appMapping);
    dumpApps();
    policy_->addApp(appMapping);
}

void PolicyManager::processRemoveEvent(std::shared_ptr<const rmcommon::RemoveEvent> event)
{
    cat_.debug("POLICYMANAGER RemoveProc event received");
    // search target
    AppMappingPtr appMapping = make_shared<AppMapping>(event->getApp());
    auto it = apps_.find(appMapping);
    if (it != end(apps_)) {
        policy_->removeApp(*it);
        apps_.erase(it);
    }
    dumpApps();
}

void PolicyManager::processTimerEvent(std::shared_ptr<const rmcommon::TimerEvent> event)
{
    cat_.debug("POLICYMANAGER timer event received");
    policy_->timer();
}

void PolicyManager::processMonitorEvent(std::shared_ptr<const rmcommon::MonitorEvent> event)
{
    ostringstream os;
    os << "POLICYMANAGER monitor event received => " << *event;
    cat_.info(os.str());
    policy_->monitor(event);
}

void PolicyManager::processFeedbackEvent(std::shared_ptr<const rmcommon::FeedbackEvent> event)
{
    using namespace rmcommon;

    KonroTimer::TimeUnit micros = KonroTimer::ElapsedFrom(event->getTimePoint());
    cat_.debug("POLICYMANAGER feedback event received for pid %d, delivered in %ld microseconds",
               event->getApp()->getPid(),
               (long)micros.count());

    AppMappingPtr appMapping = make_shared<AppMapping>(event->getApp());
    auto it = apps_.find(appMapping);
    if (it != end(apps_)) {
        policy_->feedback(*it, event->getFeedback());
    } else {
        cat_.error("POLICYMANAGER feedback event: AppMapping not found for pid %d",
                   event->getApp()->getPid());
    }
}

void PolicyManager::processSecurityEvent(std::shared_ptr<const rmcommon::SecurityEvent> event)
{
    cat_.info("POLICYMANAGER security event received for pid %d, sai=%.3f, labels=%s",
              event->getApp()->getPid(),
              event->getSai(),
              event->getLabels().c_str());

    AppMappingPtr appMapping = make_shared<AppMapping>(event->getApp());
    auto it = apps_.find(appMapping);
    if (it != end(apps_)) {
        (*it)->setSai(event->getSai());
        policy_->securityAlert(*it, event->getSai(), event->getFactors(), event->getLabels());
    } else {
        cat_.error("POLICYMANAGER security event: AppMapping not found for pid %d",
                   event->getApp()->getPid());
    }
}

void PolicyManager::processClearEvent(std::shared_ptr<const rmcommon::ClearEvent> event)
{
    pid_t pid = event->getPid();
    cat_.info("POLICYMANAGER clear event received for pid %d", pid);
    auto it = find_if(begin(apps_), end(apps_),
                      [pid](const AppMappingPtr &am) { return am->getPid() == pid; });
    if (it != end(apps_)) {
        policy_->clearApp(*it);
    } else {
        cat_.error("POLICYMANAGER clear event: AppMapping not found for pid %d", pid);
    }
}

void PolicyManager::setPolicyThresholds(const rp::PolicyThresholds &th)
{
    if (policy_)
        policy_->setThresholds(th);
}

void PolicyManager::dumpApps() const
{
    std::ostringstream os;
    os << "POLICYMANAGER handling PIDS [";
    bool first = true;
    for (auto &app: apps_) {
        if (first)
            first = false;
        else
            os << ",";
        os << app->getPid();
    }
    os << "]";
    cat_.info(os.str());
}

}   // namespace rp
