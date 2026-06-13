#ifndef SEC_SAI_H
#define SEC_SAI_H

namespace sec {

/*!
 * \brief Per-app security factors, each already normalized to [0,1].
 * Statistical factors are produced by Ewma::deviation(); discrete
 * factors (newExec) are 0 or 1.
 */
struct SecurityFactors {
    float fanout   = 0.0f;      // A1 distinct outbound destinations
    float halfOpen = 0.0f;      // A2 SYN_SENT ratio
    float forkRate = 0.0f;      // B1 process count
    float newExec  = 0.0f;      // B2 unexpected binary (discrete 0/1)
    float cpuBurst = 0.0f;      // C1 cpu usage delta
};

/*! Weights for the composite SAI; configurable, any factor can be zeroed. */
struct SaiWeights {
    float fanout = 0.30f, halfOpen = 0.25f, forkRate = 0.15f,
          newExec = 0.20f, cpuBurst = 0.10f;
};

/*!
 * \brief EWMA mean/variance baseline with a warmup gate.
 * deviation() returns 0 until WARMUP samples have been seen, then a
 * relu z-score squashed to [0,1).
 */
class Ewma {
public:
    static const int WARMUP = 5;
    void update(float x, float alpha);
    bool warming() const { return count_ < WARMUP; }
    float deviation(float x) const;
private:
    float mean_ = 0.0f;
    float var_ = 0.0f;
    int count_ = 0;
};

/*! Clamped weighted sum of the factors -> SAI in [0,1]. */
float computeSai(const SecurityFactors &f, const SaiWeights &w);

} // namespace sec

#endif // SEC_SAI_H
