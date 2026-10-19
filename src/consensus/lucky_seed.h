// Copyright (c) 2026 Lucky Lode developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT-license.php.
//
// Seed-funded operational reserves (internal/20): the faucet and the dev
// fund start from the first block like the jackpot/pot seeds, as virtual
// consensus balances spendable only through capped per-block claims to
// pinned addresses. Same pattern as lucky_pot.h: pure header-only math,
// no chain state, no consensus deps, so the KAT runner
// (`lucky_seed_kat.cpp`) compiles standalone.
//
// Rules:
//  1. Two reserves, seeded at genesis (testnet values; mainnet decided
//     at ceremony): FAUCET_SEED and DEV_SEED.
//  2. Faucet claims: any block may include coinbase outputs paying the
//     pinned faucet script, total per block <= FAUCET_CAP and <= reserve.
//  3. Dev claims: only on heights where height % DEV_EPOCH == 0, total
//     per such block <= DEV_CAP and <= reserve.
//  4. The destinations are consensus-pinned scripts (chainparams). An
//     empty pin disables that leg (allowance 0): mainnet boots inert
//     until the ceremony pins real addresses. A miner cannot redirect
//     seed funds — outputs paying anything else are not seed claims.
//  5. No refill on testnet (depleting seeds); mainnet refill is a
//     ceremony decision. Self-throttling: unclaimed allowances stay in
//     the reserves (same no-vaporize rule as the jackpot fix).
//
// Conservation: faucet_after + dev_after + faucet_claimed + dev_claimed
// == faucet_before + dev_before (saturating, never wraps).
#ifndef LUCKYLODE_LUCKY_SEED_H
#define LUCKYLODE_LUCKY_SEED_H

#include <stdint.h>

namespace lucky_seed
{

// Genesis seed funds (testnet; 1 coin = 1e8 base units). The faucet tops
// up a drip wallet; the dev fund is starter capital beside the ongoing
// 1% + 0.5pp fee streams (docs/04 §4.2).
static const uint64_t FAUCET_SEED = 10000000000000ULL; // 100,000 tLKYL
static const uint64_t DEV_SEED = 5000000000000ULL;     // 50,000 tLKYL
// Per-block faucet ceiling (a ceiling, not a schedule — the pool claims
// only what the faucet wallet needs).
static const uint64_t FAUCET_CAP = 100000000000ULL; // 1,000 tLKYL
// Dev claims land every DEV_EPOCH-th block ("salary" cadence), up to
// DEV_CAP each. 100/block average ≈ 1/block ≈ a year of testnet runway.
static const uint64_t DEV_EPOCH = 100;
static const uint64_t DEV_CAP = 10000000000ULL; // 100 tLKYL

/// Seed state carried in the block index (reorg-friendly).
struct SeedState
{
    uint64_t faucet; // faucet reserve before the block
    uint64_t dev;    // dev reserve before the block
};

/// Faucet allowance this block: capped, and bounded by the reserve.
// An empty (unpinned) destination disables the leg entirely.
inline uint64_t FaucetAllowance(uint64_t reserve, bool pinned)
{
    if (!pinned || reserve == 0)
    {
        return 0;
    }
    return reserve < FAUCET_CAP ? reserve : FAUCET_CAP;
}

/// Dev allowance this block: only on epoch heights, capped, bounded.
inline uint64_t DevAllowance(uint64_t reserve, uint64_t height, bool pinned, uint64_t epoch = DEV_EPOCH)
{
    if (!pinned || reserve == 0 || epoch == 0 || (height % epoch) != 0)
    {
        return 0;
    }
    return reserve < DEV_CAP ? reserve : DEV_CAP;
}

struct SeedPayout
{
    uint64_t faucet_claimed; // debited from the faucet reserve
    uint64_t dev_claimed;    // debited from the dev reserve
    uint64_t faucet;         // faucet reserve after
    uint64_t dev;            // dev reserve after
    bool ok;                 // false when a claim exceeds its allowance
};

/// Apply one block's seed claims. `faucet_sum`/`dev_sum` are the summed
/// coinbase outputs paying the pinned scripts (computed by the caller
/// from exact script matches — anything else is not a seed claim).
/// Saturating, never wraps; rejects (ok=false) instead of clamping an
/// over-allowance claim. `dev_epoch` defaults to the frozen spec;
/// consensus passes its effective epoch (regtest override parity).
inline SeedPayout ApplySeedBlock(uint64_t faucetReserve, uint64_t devReserve,
                                 uint64_t height, uint64_t faucetSum, uint64_t devSum,
                                 bool faucetPinned, bool devPinned,
                                 uint64_t devEpoch = DEV_EPOCH)
{
    SeedPayout p;
    uint64_t faucetAllow = FaucetAllowance(faucetReserve, faucetPinned);
    uint64_t devAllow = DevAllowance(devReserve, height, devPinned, devEpoch);
    p.ok = faucetSum <= faucetAllow && devSum <= devAllow;
    p.faucet_claimed = p.ok ? faucetSum : 0;
    p.dev_claimed = p.ok ? devSum : 0;
    p.faucet = faucetReserve >= p.faucet_claimed ? faucetReserve - p.faucet_claimed : 0;
    p.dev = devReserve >= p.dev_claimed ? devReserve - p.dev_claimed : 0;
    return p;
}

} // namespace lucky_seed

#endif // LUCKYLODE_LUCKY_SEED_H
