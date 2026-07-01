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

static int test_full_recovery_to_observe() {
    // Regression guard for FIX 1.1 (the recovery deadlock). The state machine
    // only advances on a published SecurityEvent, and the fixed monitor now
    // publishes EVERY period (including sai below the publish gate). This test
    // documents that, given those low-SAI samples, an app driven to THROTTLE
    // recovers ALL THE WAY back to OBSERVE — stepping down one level per dwellN
    // periods. If the monitor ever re-adds the publish gate, these low samples
    // would not reach step() at runtime and recovery would silently stall.
    PolicyThresholds th;                 // t1=.4 t2=.6 t3=.8 dwellN=3
    StateTracker s;
    if (s.step(0.50f, th, 0.0f) != SecState::THROTTLE) return TEST_FAILED;
    // sustained low SAI: dwellN-1 periods stay in THROTTLE, then step down
    if (s.step(0.0f, th, 0.0f) != SecState::THROTTLE) return TEST_FAILED; // 1
    if (s.step(0.0f, th, 0.0f) != SecState::THROTTLE) return TEST_FAILED; // 2
    if (s.step(0.0f, th, 0.0f) != SecState::OBSERVE)  return TEST_FAILED; // 3 -> OBSERVE
    // and it stays at OBSERVE afterwards
    if (s.step(0.0f, th, 0.0f) != SecState::OBSERVE)  return TEST_FAILED;
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

/* Documents that thresholds are data-driven: custom cut-offs are honoured. */
static int test_custom_thresholds() {
    PolicyThresholds th;
    th.t1 = 0.5f; th.t2 = 0.7f; th.t3 = 0.9f; th.dwellN = 2;
    StateTracker s;
    // 0.45 is below t1=0.50 -> stays OBSERVE
    if (s.step(0.45f, th, 0.0f) != SecState::OBSERVE)    return TEST_FAILED;
    // 0.55 is above t1 but below t2 -> THROTTLE
    if (s.step(0.55f, th, 0.0f) != SecState::THROTTLE)   return TEST_FAILED;
    // 0.95 is above t3 -> QUARANTINE (escalation is immediate)
    if (s.step(0.95f, th, 0.0f) != SecState::QUARANTINE) return TEST_FAILED;
    return TEST_OK;
}

int main() {
    int rc = 0;
    rc |= test_escalation();
    rc |= test_tolerance_offset_raises_thresholds();
    rc |= test_hysteresis_dwell_before_recover();
    rc |= test_full_recovery_to_observe();
    rc |= test_quarantine_is_sticky();
    rc |= test_custom_thresholds();
    std::cout << (rc == TEST_OK ? "ALL PASS" : "FAIL") << std::endl;
    return rc;
}
