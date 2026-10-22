// Copyright (c) 2026 Lucky Lode developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php
//
// Prize Fund + Luckynode Draw money rules (doc 06 §6.7, rev 1.3) —
// exact executable mirror of the Rust reference `lm-rewards::prize`.
// The prize fund is the third consensus fund: the jackpot-levy slice
// that overflows the reserve cap is credited to it every block (it was
// unspendable bookkeeping before rev 1.3), and only Luckynode Draw
// claims spend it. All amounts are base units (uint64); all division
// floors; intermediates saturate, never wrap. Pure header-only math:
// no chain state, no consensus deps, so the KAT runner
// (`lucky_prize_kat.cpp`) compiles standalone.
#ifndef LUCKYLODE_LUCKY_PRIZE_H
#define LUCKYLODE_LUCKY_PRIZE_H

#include <stdint.h>
#include <string>
#include <vector>
#include <utility>
#include <string.h>

namespace lucky_prize
{

// Genesis seed: 1,000 LKYL (doc 06 §6.7.1 — same consensus-locked
// pattern as the jackpot/pot seeds; mainnet value finalized at the
// ceremony).
static const uint64_t PRIZE_SEED = 100000000000ULL;

// Draw budget: slice of the trailing epoch's prize inflow, per-myriad
// (1000 = 10%, frozen — the pool-era v1 default).
static const uint64_t PRIZE_SLICE_BPS = 1000;
static const uint64_t PRIZE_SLICE_DENOM = 10000;

/// Credit one block's overflow into the fund (saturating).
inline uint64_t Credit(uint64_t balance, uint64_t overflow)
{
    uint64_t s = balance + overflow;
    return s < balance ? ~uint64_t(0) : s;
}

/// Prize inflow over a trailing window: the fund moved from
/// `balance_then` to `balance_now` while `claims` left it, so the
/// inflow is the rise plus what was drained (saturating: a window that
/// starts after a drain under-counts only when claims exceed credit,
/// which the caller caps by construction).
inline uint64_t TrailingInflow(uint64_t balance_now, uint64_t balance_then, uint64_t claims)
{
    // credits = (balance_now - balance_then) + claims, signed, floored
    // at zero: a window that starts after a large drain can under-count,
    // which only makes the budget smaller — fail-safe.
    __int128_t delta = (__int128_t)balance_now - (__int128_t)balance_then + (__int128_t)claims;
    return delta > 0 ? (uint64_t)delta : 0;
}

/// Draw budget: the slice of the trailing inflow, capped at the fund
/// balance (a draw may only spend what the fund holds). Zero inflow
/// means zero budget — self-throttling, no pity timer.
inline uint64_t Budget(uint64_t inflow, uint64_t balance, uint64_t slice_bps)
{
    __uint128_t slice = (__uint128_t)inflow * (__uint128_t)slice_bps / (__uint128_t)PRIZE_SLICE_DENOM;
    return slice > (__uint128_t)balance ? balance : (uint64_t)slice;
}

/// Deterministic tenure-weighted winner over the entrant set:
/// `r = u64(seed[..8] LE) % total-weight`, walked id-ascending — the
// byte-for-byte mirror of the pool-era v1 `draw_winner` (lm-luckynode),
/// kept identical so the promotion changes no selection math. Returns
/// the winning id; empty entrants or zero total return "".
inline std::string Winner(const std::vector<std::pair<std::string, uint64_t>> &entrants, const uint8_t seed[32])
{
    if (entrants.empty())
        return "";
    unsigned __int128 total = 0;
    for (size_t i = 0; i < entrants.size(); i++)
    {
        total += (unsigned __int128)entrants[i].second;
    }
    if (total == 0)
        return "";
    uint64_t low;
    memcpy(&low, seed, 8); // seed[..8] little-endian, same as Rust
    unsigned __int128 r = (unsigned __int128)low % total;
    for (size_t i = 0; i < entrants.size(); i++)
    {
        unsigned __int128 w = (unsigned __int128)entrants[i].second;
        if (r < w)
            return entrants[i].first;
        r -= w;
    }
    return entrants.back().first;
}

} // namespace lucky_prize

#endif // LUCKYLODE_LUCKY_PRIZE_H
