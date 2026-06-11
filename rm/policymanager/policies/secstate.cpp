#include "secstate.h"

namespace rp {

static SecState target(float sai, const PolicyThresholds &th, float off) {
    if (sai >= th.t3 + off) return SecState::QUARANTINE;
    if (sai >= th.t2 + off) return SecState::RESTRICT;
    if (sai >= th.t1 + off) return SecState::THROTTLE;
    return SecState::OBSERVE;
}

SecState StateTracker::step(float sai, const PolicyThresholds &th, float tolOffset) {
    if (state_ == SecState::QUARANTINE)        // sticky: manual clear only
        return state_;

    SecState tgt = target(sai, th, tolOffset);
    if (tgt > state_) {                        // escalate immediately
        state_ = tgt;
        belowCount_ = 0;
    } else if (tgt < state_) {                 // recover with dwell
        if (++belowCount_ >= th.dwellN) {
            state_ = static_cast<SecState>(static_cast<int>(state_) - 1);
            belowCount_ = 0;
        }
    } else {
        belowCount_ = 0;
    }
    return state_;
}

void StateTracker::clear() {
    state_ = SecState::OBSERVE;
    belowCount_ = 0;
}

} // namespace rp
