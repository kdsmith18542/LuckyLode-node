// Lucky Lode pre-committable draws (doc 06 rev 1.2).
//
// The lottery ticket is the PARENT block's hash, mixed with the height:
//
//   draw_digest = SHA256D(hashPrevBlock_internal_32B || height_le32)
//   jackpot     iff draw_digest < floor(2^256 / JACKPOT_ODDS)
//   pot event   iff draw_digest < floor(2^256 / POT_ODDS)
//   tier        =  draw_digest mod 100
//
// Why the parent hash (2026-10-14 fix): the original trigger compared the
// block's OWN PoW digest to T/odds, which is only known AFTER grinding — a
// bonus-bearing coinbase then had to be committed in advance, so claim
// pools had to withhold ~99% of their finds (uneconomic at real odds; the
// reserve never paid). The parent hash is fixed before grinding, so a pool
// knows the draw class of the next height at template time, builds the
// claim coinbase for that height, and submits every find. SHA256D mixing
// makes the digest uniform over 2^256 regardless of the parent's own
// target (PoW parents are bounded by their target; PoS parents are not),
// so the odds are exactly 1/JACKPOT_ODDS and 1/POT_ODDS of all heights —
// never drifting with difficulty.
//
// The miner cannot influence the draw: hashPrevBlock is fixed by the
// parent's PoW, and grinding a parent whose child is a jackpot costs
// ~JACKPOT_ODDS parent-blocks of work for one bonus (irrational).
//
// PoS blocks are exempt (locked 2026-10-13: draws are PoW-finder-only);
// the draw digest is still well-defined for them, the caller gates it.

#ifndef LUCKY_DRAW_H
#define LUCKY_DRAW_H

#include "uint256.h"
#include "arith_uint256.h"
#include "crypto/sha256.h"
#include <stdint.h>
#include <string.h>

namespace lucky_draw
{

static const uint64_t JACKPOT_ODDS = 100;
static const uint64_t POT_ODDS = 1000;

// draw_digest = SHA256D(parent hash (internal byte order) || height LE32).
// The result is a uint256 whose numeric (arith) value is the standard
// big-endian interpretation of the hash — the same convention as the PoW
// digest comparisons (doc 05 §5.1).
static inline uint256 Digest(const uint256 &prevHash, int32_t height)
{
    unsigned char buf[36];
    memcpy(buf, prevHash.begin(), 32);
    uint32_t h = (uint32_t)height;
    buf[32] = (unsigned char)(h & 0xff);
    buf[33] = (unsigned char)((h >> 8) & 0xff);
    buf[34] = (unsigned char)((h >> 16) & 0xff);
    buf[35] = (unsigned char)((h >> 24) & 0xff);
    uint256 first;
    CSHA256().Write(buf, 36).Finalize(first.begin());
    uint256 second;
    CSHA256().Write(first.begin(), 32).Finalize(second.begin());
    // CSHA256 writes the digest in standard (big-endian display) order;
    // uint256 stores internal little-endian, so reverse for the numeric
    // value to equal the big-endian hash.
    uint256 out;
    for (int i = 0; i < 32; i++)
        out.begin()[i] = second.begin()[31 - i];
    return out;
}

// floor(2^256 / divisor), divisor >= 1. Max() = 2^256 - 1, so
// Max()/divisor == floor((2^256 - 1)/divisor) == floor(2^256/divisor)
// for all divisor >= 1 (2^256 is divisible by no divisor > 1 except
// powers of two, and the -1 only matters for exact divisors).
static inline arith_uint256 Threshold(uint64_t divisor)
{
    return (~arith_uint256(0)) / (divisor < 1 ? 1 : divisor);
}

static inline bool Jackpot(const uint256 &digest, uint64_t divisor)
{
    return UintToArith256(digest) < Threshold(divisor);
}

static inline bool PotEvent(const uint256 &digest, uint64_t divisor)
{
    return UintToArith256(digest) < Threshold(divisor);
}

// tier = draw_digest mod 100 (pot payout band: 0-69 / 70-94 / 95-99).
static inline uint64_t Tier(const uint256 &digest)
{
    arith_uint256 d = UintToArith256(digest);
    arith_uint256 hundred(100);
    return (d - (d / hundred) * hundred).GetLow64();
}

} // namespace lucky_draw

#endif // LUCKY_DRAW_H
