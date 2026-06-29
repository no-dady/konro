#include <iostream>
#include <cmath>
#include "sai.h"

#define TEST_OK 0
#define TEST_FAILED 1
using namespace sec;

static int test_ewma_warmup() {
    Ewma e;
    // before warmup, deviation is 0 regardless of input
    e.update(10.0f, 0.3f);
    if (!e.warming()) return TEST_FAILED;          // 1 sample => still warming
    if (e.deviation(1000.0f) != 0.0f) return TEST_FAILED;
    return TEST_OK;
}

static int test_ewma_deviation_after_warmup() {
    Ewma e;
    for (int i = 0; i < Ewma::WARMUP; ++i) e.update(10.0f, 0.3f);
    if (e.warming()) return TEST_FAILED;
    // a value equal to the mean has zero deviation
    if (e.deviation(10.0f) > 0.01f) return TEST_FAILED;
    // a large spike maps toward 1.0
    float d = e.deviation(10000.0f);
    if (d < 0.9f || d > 1.0f) return TEST_FAILED;
    // a value below the mean clamps to 0 (relu)
    if (e.deviation(0.0f) != 0.0f) return TEST_FAILED;
    return TEST_OK;
}

static int test_compute_sai_weighted_clamp() {
    SaiWeights w; w.fanout = 0.4f; w.halfOpen = 0.3f; w.forkRate = 0.1f;
    w.newExec = 0.5f; w.cpuBurst = 0.1f; w.egress = 0.15f; w.memGrowth = 0.1f;
    SecurityFactors f; f.fanout = 1.0f; f.halfOpen = 1.0f; f.forkRate = 1.0f;
    f.newExec = 1.0f; f.cpuBurst = 1.0f; f.egress = 1.0f; f.memGrowth = 1.0f;
    // sum of weights = 1.65 -> clamps to 1.0
    if (std::fabs(computeSai(f, w) - 1.0f) > 0.001f) return TEST_FAILED;
    SecurityFactors z;   // all 7 factors zero
    if (computeSai(z, w) != 0.0f) return TEST_FAILED;
    return TEST_OK;
}

// Each new factor contributes exactly its weight when the others are zero,
// and the result stays within [0,1] (no clamp at this magnitude).
static int test_compute_sai_new_factors() {
    SaiWeights w;   // all other weights present but their factors are 0
    SecurityFactors f;
    f.egress = 1.0f;
    if (std::fabs(computeSai(f, w) - w.egress) > 0.001f) return TEST_FAILED;
    SecurityFactors g;
    g.memGrowth = 1.0f;
    if (std::fabs(computeSai(g, w) - w.memGrowth) > 0.001f) return TEST_FAILED;
    // a zeroed weight disables the factor even at full magnitude
    SaiWeights wz; wz.egress = 0.0f; wz.memGrowth = 0.0f;
    SecurityFactors h; h.egress = 1.0f; h.memGrowth = 1.0f;
    if (computeSai(h, wz) != 0.0f) return TEST_FAILED;
    return TEST_OK;
}

int main() {
    int rc = 0;
    rc |= test_ewma_warmup();
    rc |= test_ewma_deviation_after_warmup();
    rc |= test_compute_sai_weighted_clamp();
    rc |= test_compute_sai_new_factors();
    std::cout << (rc == TEST_OK ? "ALL PASS" : "FAIL") << std::endl;
    return rc;
}
