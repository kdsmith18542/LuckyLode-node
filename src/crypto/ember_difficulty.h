// Copyright (c) 2026 Lucky Lode developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// LuckyHash difficulty: exact integer LWMA retarget (doc 05 §5.3 rev 1.1).
// Normative reference: Rust `lm-pow::difficulty::lwma_next_target`; the KAT
// runner (`ember_diff_kat.cpp`) must agree on every vector.
//
//   acc  = Σ clamp(times[i]-times[i-1], 0, 6T) * i,  i = 1..=60
//   avg  = Σ targets / 60
//   raw  = avg * acc / (T * K)        (exact; saturates at 2^256-1)
//   next = clamp(raw, last - last/3, last + last/3)
//   next = min(next, POW_LIMIT)
//
// No floats anywhere: byte-identical results on every architecture are a
// consensus requirement. The division uses the exact decomposition
// floor(avg*acc/D) = q*acc + floor(r*acc/D) with q = avg/D, r = avg%D
// (r < D < 2^17, acc < 2^20 ⇒ the remainder product fits in u64).

#ifndef LUCKYLODE_EMBER_DIFFICULTY_H
#define LUCKYLODE_EMBER_DIFFICULTY_H

#include "arith_uint256.h"
#include <stdint.h>
#include <stddef.h>

namespace ember
{
    static const size_t LWMA_N = 60;
    static const uint64_t LWMA_T = 60;
    static const uint64_t LWMA_K = 1830; // N(N+1)/2
    static const uint64_t SOLVETIME_CLAMP = 6 * LWMA_T;
    static const uint64_t ADJUST_DENOM = 3;

    /** Easiest allowed target: compact 0x1f00ffff expansion. */
    arith_uint256 PowLimit();

    /**
     * LWMA next target (doc 05 §5.3). `targets` oldest→newest (must be
     * LWMA_N), `times` unix seconds (must be LWMA_N+1; times[0] parents the
     * first block). Returns false on wrong lengths only.
     */
    bool LwmaNextTarget(arith_uint256 &next,
                        const arith_uint256 *targets, size_t nTargets,
                        const int64_t *times, size_t nTimes);
}

#endif // LUCKYLODE_EMBER_DIFFICULTY_H
