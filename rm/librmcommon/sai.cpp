#include "sai.h"
#include <algorithm>
#include <cmath>

namespace sec {

void Ewma::update(float x, float alpha) {
    if (count_ == 0) {
        mean_ = x;
        var_ = 0.0f;
    } else {
        float d = x - mean_;
        mean_ += alpha * d;
        var_ = (1.0f - alpha) * (var_ + alpha * d * d);
    }
    ++count_;
}

float Ewma::deviation(float x) const {
    if (warming()) return 0.0f;
    float sd = std::sqrt(var_) + 1e-6f;
    float z = (x - mean_) / sd;             // relu: ignore values below baseline
    if (z <= 0.0f) return 0.0f;
    return 1.0f - std::exp(-z * 0.5f);      // monotonic squash to [0,1)
}

static float clamp01(float v) {
    return std::max(0.0f, std::min(1.0f, v));
}

float computeSai(const SecurityFactors &f, const SaiWeights &w) {
    return clamp01(w.fanout * f.fanout +
                   w.halfOpen * f.halfOpen +
                   w.forkRate * f.forkRate +
                   w.newExec * f.newExec +
                   w.cpuBurst * f.cpuBurst +
                   w.egress * f.egress +
                   w.memGrowth * f.memGrowth +
                   w.rawSocket * f.rawSocket);
}

} // namespace sec
