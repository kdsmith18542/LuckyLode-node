// Copyright (c) 2026 Lucky Lode developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Jackpot money rules (doc 06 §6.2) — exact executable mirror of the
// Rust reference `lm-rewards::reserve`. All amounts are base units
// (uint64); all division floors; intermediates saturate, never wrap.
// Pure header-only math: no chain state, no consensus deps, so the KAT
// runner (`ember_jackpot_kat.cpp`) compiles standalone.
#ifndef LUCKYLODE_JACKPOT_H
#define LUCKYLODE_JACKPOT_H

#include <stdint.h>

namespace jackpot
{

static const uint64_t LEVY_PERMYRIAD = 500;   // 5% of R+F into the reserve
static const uint64_t LEVY_DENOM = 10000;
static const uint64_t BONUS_MULT = 5;         // bonus = 5 * R from reserve
static const uint64_t RESERVE_CAP_MULT = 50;  // cap = 50 * R at current R

struct Payout
{
    uint64_t miner;       // total coinbase value for the finder
    uint64_t bonus;       // jackpot bonus included in miner (0 normally)
    uint64_t to_reserve;  // levy slice credited to the reserve
    uint64_t to_league;   // levy slice overflowing to the league pool
    uint64_t reserve;     // reserve balance after this block
};

inline uint64_t sat_add(uint64_t a, uint64_t b)
{
    uint64_t s = a + b;
    return s < a ? ~uint64_t(0) : s;
}

inline uint64_t sat_mul(uint64_t a, uint64_t b)
{
    __uint128_t p = (__uint128_t)a * (__uint128_t)b;
    return p > ~uint64_t(0) ? ~uint64_t(0) : (uint64_t)p;
}

/// Per-block levy: floor((base + fees) * 500 / 10000).
inline uint64_t Levy(uint64_t base, uint64_t fees)
{
    __uint128_t inflow = (__uint128_t)sat_add(base, fees);
    return (uint64_t)(inflow * LEVY_PERMYRIAD / LEVY_DENOM);
}

/// Reserve cap at the block's own base reward: 50 * R (saturating).
inline uint64_t ReserveCap(uint64_t base)
{
    return sat_mul(base, RESERVE_CAP_MULT);
}

/// Jackpot bonus available from a balance: min(5 * R, reserve).
inline uint64_t JackpotBonus(uint64_t base, uint64_t reserve)
{
    uint64_t full = sat_mul(base, BONUS_MULT);
    return full < reserve ? full : reserve;
}

/// One block's money transition. Order (doc 06 §6.2): levy first (capped,
/// overflow to league), then the jackpot bonus from the credited reserve.
/// Conservation: miner + (reserve - reserve_before) + to_league == R + F.
inline Payout ApplyBlock(uint64_t reserve, uint64_t base, uint64_t fees, bool isJackpot)
{
    uint64_t levy = Levy(base, fees);
    uint64_t inflow = sat_add(base, fees);
    uint64_t normal = inflow >= levy ? inflow - levy : 0;
    uint64_t cap = ReserveCap(base);
    uint64_t room = cap >= reserve ? cap - reserve : 0;
    uint64_t to_reserve = levy < room ? levy : room;
    uint64_t to_league = levy - to_reserve;
    uint64_t credited = reserve + to_reserve; // cannot overflow: to_reserve <= cap - reserve
    Payout p;
    p.to_reserve = to_reserve;
    p.to_league = to_league;
    if (!isJackpot)
    {
        p.miner = normal;
        p.bonus = 0;
        p.reserve = credited;
        return p;
    }
    uint64_t bonus = JackpotBonus(base, credited);
    p.bonus = bonus;
    p.miner = sat_add(normal, bonus);
    p.reserve = credited - bonus;
    return p;
}

} // namespace jackpot

#endif // LUCKYLODE_JACKPOT_H
