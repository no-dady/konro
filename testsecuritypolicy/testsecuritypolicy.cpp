#include <iostream>
#include "secstate.h"

#define TEST_OK 0
#define TEST_FAILED 1
using namespace rp;

static int test_escalation() {
    PolicyThresholds th;                 // t1=.4 t2=.6 t3=.8 margin=.1 dwellN=3
    StateTracker s;
    if (s.step(0.30f, th, 0.0f) != SecState::OBSERVE) return TEST_FAILED;
    if (s.step(0.50f, th, 0.0f) != SecState::THROTTLE) return TEST_FAILED;
    if (s.step(0.70f, th, 0.0f) != SecState::RESTRICT) return TEST_FAILED;
    if (s.step(0.90f, th, 0.0f) != SecState::QUARANTINE) return TEST_FAILED;
    return TEST_OK;
}

static int test_tolerance_offset_raises_thresholds() {
    PolicyThresholds th;
    StateTracker s;
    // offset +0.15 -> t1 effectively 0.55, so 0.50 stays OBSERVE
    if (s.step(0.50f, th, 0.15f) != SecState::OBSERVE) return TEST_FAILED;
    return TEST_OK;
}

static int test_hysteresis_dwell_before_recover() {
    PolicyThresholds th;
    StateTracker s;
    s.step(0.70f, th, 0.0f);                       // RESTRICT
    // SAI drops below t2-margin, but must dwell dwellN periods
    if (s.step(0.40f, th, 0.0f) != SecState::RESTRICT) return TEST_FAILED; // 1
    if (s.step(0.40f, th, 0.0f) != SecState::RESTRICT) return TEST_FAILED; // 2
    if (s.step(0.40f, th, 0.0f) != SecState::THROTTLE) return TEST_FAILED; // 3 -> step down one
    return TEST_OK;
}

static int test_quarantine_is_sticky() {
    PolicyThresholds th;
    StateTracker s;
    s.step(0.90f, th, 0.0f);                       // QUARANTINE
    // even sustained low SAI never auto-recovers from quarantine
    for (int i = 0; i < 10; ++i)
        if (s.step(0.0f, th, 0.0f) != SecState::QUARANTINE) return TEST_FAILED;
    s.clear();                                     // manual /clear
    if (s.state() != SecState::OBSERVE) return TEST_FAILED;
    return TEST_OK;
}

int main() {
    int rc = 0;
    rc |= test_escalation();
    rc |= test_tolerance_offset_raises_thresholds();
    rc |= test_hysteresis_dwell_before_recover();
    rc |= test_quarantine_is_sticky();
    std::cout << (rc == TEST_OK ? "ALL PASS" : "FAIL") << std::endl;
    return rc;
}
