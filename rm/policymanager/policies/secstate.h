#ifndef SECSTATE_H
#define SECSTATE_H

namespace rp {

/*! Graduated containment states, ordered by severity. */
enum class SecState { OBSERVE = 0, THROTTLE = 1, RESTRICT = 2, QUARANTINE = 3 };

/*! Escalation thresholds on SAI plus hysteresis parameters. */
struct PolicyThresholds {
    float t1 = 0.4f, t2 = 0.6f, t3 = 0.8f;  // escalation cut-offs
    float margin = 0.1f;                    // hysteresis gap (reserved)
    int dwellN = 3;                         // periods below before stepping down
};

/*!
 * \brief Per-app containment state machine. Pure: no cgroup/IO.
 *
 * Escalation is immediate; recovery requires the target state to stay
 * lower for dwellN consecutive steps (hysteresis). QUARANTINE is sticky
 * and only cleared by clear() (manual operator action). tolOffset raises
 * all thresholds for gentler (higher) security levels.
 */
class StateTracker {
public:
    SecState step(float sai, const PolicyThresholds &th, float tolOffset);
    SecState state() const { return state_; }
    void clear();
private:
    SecState state_ = SecState::OBSERVE;
    int belowCount_ = 0;
};

} // namespace rp

#endif // SECSTATE_H
