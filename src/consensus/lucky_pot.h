// Copyright (c) 2026 Lucky Lode developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Lucky Pot money rules (see doc 06) —
// exact executable mirror of the Rust reference `lm-rewards::pot`. All
// amounts are base units (uint64); all division floors; intermediates
// saturate, never wrap. Pure header-only math: no chain state, no
// consensus deps, so the KAT runner (`lucky_pot_kat.cpp`) compiles
// standalone.
//
// Rules:
//  1. The 5% levy (unchanged total) splits 4/5 jackpot reserve, 1/5 pot:
//     pot_levy = floor(levy / 5), jackpot_levy = levy - pot_levy.
//  2. Pot slice credits up to the cap (200 * R); the excess BURNS.
//  3. Pot event iff the block digest < T/1000; tier = digest mod 100:
//     0-69 -> 10% of pot, 70-94 -> 25%, 95-99 -> 50%.
//  4. Pity timer: after 4320 event-less blocks the next PoW block pays
//     a forced tier-A (10%) splash — PoW finders only (rule: jackpots
//     and pot payouts never pay a staker; a PoS block at the limit
//     counts the drought and collects nothing).
//  5. Jackpot leg is unchanged (jackpot.h formulas, jackpot slice).
//
// Conservation: miner + (reserve - reserve_before) + (pot - pot_before)
// + to_prize + to_burn == R + F.
#ifndef LUCKYLODE_LUCKY_POT_H
#define LUCKYLODE_LUCKY_POT_H

#include "consensus/jackpot.h"

#include <stdint.h>

namespace lucky_pot
{

static const uint64_t POT_SPLIT_DEN = 5;      // pot share of the levy: 1/5
static const uint64_t POT_CAP_MULT = 200;     // cap = 200 * R at current R
static const uint64_t TIER_A_MAX = 70;        // rolls < 70 pay a tenth
static const uint64_t TIER_B_MAX = 95;        // rolls < 95 pay a quarter
static const uint64_t POT_DROUGHT_LIMIT = 4320; // ~3 days at 60s blocks

// Genesis game-fund seed: the initial balances block 1
// sees as its parent state. Consensus-locked, spendable only through the
// payout rules, miners-only — the only genesis allocation. Sized in
// max-payouts, not % of (infinite) supply: ≈100 max jackpots + pot
// equilibrium at the launch reward (docs/06 §6.6; frozen at the genesis
// ceremony). 1 coin = 1e8 base units.
// Genesis game-fund seed — LOCKED 2026-10-13 for the locked emission curve
// (peak 16 LKYL/block): jackpot seed = 100 max-payouts (100 × 5R = 8,000
// LKYL); pot seed = the pot equilibrium at R=16 (≈ 1,000 LKYL). Consensus
// state at height 0, spendable only through the jackpot/pot payout rules.
// Total ≈ 9,000 LKYL ≈ 0.1% of year-one issuance (docs/04 §4.1 guideline).
static const uint64_t JACKPOT_SEED = 800000000000ULL; // 8,000 LKYL
static const uint64_t LUCKY_SEED = 100000000000ULL;   // 1,000 LKYL

/// Pot state carried in the block index (reorg-friendly).
struct PotState
{
    uint64_t pot;      // pot balance before the block
    uint64_t drought;  // consecutive event-less blocks before this one
};

/// The block's pre-decided draws from the digest (node computes these).
struct BlockDraws
{
    bool jackpot;    // digest < T/100
    bool pot_event;  // digest < T/1000
    uint64_t tier;   // digest mod 100
    bool isPow;      // PoW finder: gates the drought-forced splash
};

struct PotPayout
{
    uint64_t miner;         // total coinbase ceiling for the finder
    uint64_t jackpot_bonus; // jackpot bonus included (0 normally)
    uint64_t pot_splash;    // pot splash included (0 without an event)
    uint64_t to_reserve;    // jackpot-levy slice credited to the reserve
    uint64_t to_pot;        // pot-levy slice credited to the pot
    uint64_t to_burn;       // pot-levy slice burned (pot cap overflow)
    uint64_t to_prize;     // jackpot-levy slice overflowing to the prize fund
    uint64_t reserve;       // jackpot reserve after (as if fully claimed)
    uint64_t pot;           // pot after (as if fully claimed)
    uint64_t drought;       // event-less run after this block (0 at event)
    bool pot_event;         // a pot event happened (digest or pity)
    bool pity;              // the event was forced by the pity timer
};

/// Pot cap at the block's current base reward: 200 * R (saturating).
inline uint64_t PotCap(uint64_t base)
{
    return jackpot::sat_mul(base, POT_CAP_MULT);
}

/// Pot payout fraction for a tier roll: (1,10), (1,4), or (1,2). Rolls
/// >= 100 are caller error territory; they pay the top tier (never
/// panic in consensus).
inline void PotFraction(uint64_t tier, uint64_t &num, uint64_t &den)
{
    if (tier < TIER_A_MAX)
    {
        num = 1;
        den = 10;
    }
    else if (tier < TIER_B_MAX)
    {
        num = 1;
        den = 4;
    }
    else
    {
        num = 1;
        den = 2;
    }
}

/// Apply one block's money rules with the Lucky Pot. The node decides
/// `draws`; this function applies the pity timer, the 4/1 split, both
/// caps, the tiers, and exact conservation. `drought_limit` defaults to
/// the frozen spec (4320); regtest may override it to prove the pity
/// path live — testnet/mainnet must not.
inline PotPayout ApplyPotBlock(uint64_t reserve, PotState state, uint64_t base, uint64_t fees,
                               BlockDraws draws, uint64_t drought_limit = POT_DROUGHT_LIMIT)
{
    uint64_t levy = jackpot::Levy(base, fees);
    uint64_t inflow = jackpot::sat_add(base, fees);
    uint64_t normal = inflow >= levy ? inflow - levy : 0;
    // Exact split: pot takes the floor fifth, jackpot keeps the rest.
    uint64_t pot_levy = levy / POT_SPLIT_DEN;
    uint64_t jackpot_levy = levy - pot_levy;

    // Jackpot leg (jackpot.h formulas, jackpot slice of the levy).
    uint64_t cap = jackpot::ReserveCap(base);
    uint64_t room = cap >= reserve ? cap - reserve : 0;
    uint64_t to_reserve = jackpot_levy < room ? jackpot_levy : room;
    uint64_t to_prize = jackpot_levy - to_reserve;
    uint64_t credited_reserve = reserve + to_reserve;
    uint64_t bonus = draws.jackpot ? jackpot::JackpotBonus(base, credited_reserve) : 0;

    // Pot leg (cap overflow burns instead of feeding the prize fund).
    uint64_t pcap = PotCap(base);
    uint64_t proom = pcap >= state.pot ? pcap - state.pot : 0;
    uint64_t to_pot = pot_levy < proom ? pot_levy : proom;
    uint64_t to_burn = pot_levy - to_pot;
    uint64_t credited_pot = state.pot + to_pot;
    // Pity: force a tier-A splash after a full drought — PoW finders
    // only (jackpot/pot payouts never pay a staker, the forced splash
    // included); a digest event at any tier resets the run and never
    // forces.
    bool pity = draws.isPow && !draws.pot_event && state.drought >= drought_limit;
    bool pot_event = draws.pot_event || pity;
    uint64_t splash = 0;
    if (pot_event)
    {
        uint64_t num = 0, den = 1;
        PotFraction(pity ? 0 : draws.tier, num, den);
        splash = (uint64_t)((__uint128_t)credited_pot * num / den);
    }

    PotPayout p;
    p.miner = jackpot::sat_add(jackpot::sat_add(normal, bonus), splash);
    p.jackpot_bonus = bonus;
    p.pot_splash = splash;
    p.to_reserve = to_reserve;
    p.to_pot = to_pot;
    p.to_burn = to_burn;
    p.to_prize = to_prize;
    p.reserve = credited_reserve - bonus;
    p.pot = credited_pot - splash;
    p.drought = pot_event ? 0 : jackpot::sat_add(state.drought, 1);
    p.pot_event = pot_event;
    p.pity = pity;
    return p;
}

} // namespace lucky_pot

#endif // LUCKYLODE_LUCKY_POT_H
