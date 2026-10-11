// (C) 2026 Lowmine developers — MIT, see COPYING.
// EmberHash difficulty: see ember_difficulty.h.

#include "crypto/ember_difficulty.h"
#include "uint256.h" // base_blob definition (arith_uint256.h only forward-declares)

namespace ember
{

arith_uint256 PowLimit()
{
    // Compact 0x1f00ffff expansion: BE bytes 00 00 ff ff 00 ... 00.
    uint256 v;
    v.SetNull();
    unsigned char *p = v.begin(); // little-endian internal order
    p[29] = 0xff;                 // BE byte 2
    p[28] = 0xff;                 // BE byte 3
    return UintToArith256(v);
}

bool LwmaNextTarget(arith_uint256 &next,
                    const arith_uint256 *targets, size_t nTargets,
                    const int64_t *times, size_t nTimes)
{
    if (nTargets != LWMA_N || nTimes != LWMA_N + 1)
    {
        return false;
    }

    // acc = Σ clamp(times[i]-times[i-1], 0, 6T) * i, i = 1..=60
    uint64_t acc = 0;
    for (size_t i = 1; i <= LWMA_N; i++)
    {
        int64_t st = times[i] > times[i - 1] ? times[i] - times[i - 1] : 0;
        if (st > (int64_t)SOLVETIME_CLAMP)
        {
            st = (int64_t)SOLVETIME_CLAMP;
        }
        acc += (uint64_t)st * (uint64_t)i;
    }

    // avg = Σ targets / 60 (floor)
    arith_uint256 sum(0);
    for (size_t i = 0; i < LWMA_N; i++)
    {
        sum += targets[i];
    }
    arith_uint256 avg = sum / (uint64_t)LWMA_N;

    // raw = avg * acc / (T * K), exact with saturation at 2^256-1.
    arith_uint256 raw(0);
    if (acc != 0)
    {
        const uint64_t D = LWMA_T * LWMA_K; // 109800 < 2^17
        arith_uint256 bnD(D);
        arith_uint256 q = avg / bnD;
        arith_uint256 r = avg - q * bnD;
        // r < D < 2^17 and acc < 2^20: this product fits in u64.
        uint64_t rb = (uint64_t)(((__uint128_t)r.GetLow64() * (__uint128_t)acc) / (__uint128_t)D);
        arith_uint256 bnAcc(acc);
        arith_uint256 bnRb(rb);
        arith_uint256 bnMax = ~arith_uint256(0);
        if (q > (bnMax - bnRb) / bnAcc)
        {
            raw = bnMax; // saturate (unreachable in practice; doc 05 §5.3)
        }
        else
        {
            raw = q * bnAcc + bnRb;
        }
    }

    // next = clamp(raw, last - last/3, last + last/3), then min(POW_LIMIT)
    arith_uint256 last = targets[LWMA_N - 1];
    arith_uint256 lo = last - last / (uint64_t)ADJUST_DENOM;
    arith_uint256 hi = last + last / (uint64_t)ADJUST_DENOM;
    arith_uint256 out = raw < lo ? lo : (raw > hi ? hi : raw);
    arith_uint256 limit = PowLimit();
    if (out > limit)
    {
        out = limit;
    }
    next = out;
    return true;
}

} // namespace ember
