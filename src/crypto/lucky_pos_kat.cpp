// KAT gate for solo-PoS liveness (internal/22): bounded stake attempts
// carried in PoS nonce bits 32..39, mixed into the entropy derivation.
// Covers: mask algebra, legacy bit-identity (pre-change frozen vectors
// generated from verus@{pre-change}:src/primitives/nonce.cpp via oracle),
// attempt sensitivity + round-trip, validation-matrices both rules.
// Build & run: verus/src/crypto/lucky_kat.sh (runs all gates).

#include "primitives/nonce.h"
#include "uint256.h"
#include "arith_uint256.h"

// Stand-in for utilstrencodings::HexDigit, as in the other KAT gates.
signed char HexDigit(char c)
{
    if (c >= '0' && c <= '9') return (signed char)(c - '0');
    if (c >= 'a' && c <= 'f') return (signed char)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (signed char)(c - 'A' + 10);
    return -1;
}

// Stand-in for chainparams.cpp's _IsVerusMainnetActive (nonce.cpp references
// it via NewNonceActive/NewPOSActive). Our chains are never Verus mainnet,
// so it returns false — matching live behavior on LUCKYLODE(TEST).
bool _IsVerusMainnetActive() { return false; }

#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond) do { if (!(cond)) { failures++; printf("FAIL line %d: %s\n", __LINE__, #cond); } else { printf("ok   line %d\n", __LINE__); } } while (0)

static uint256 Repeat(unsigned char b)
{
    uint256 u;
    memset(u.begin(), b, 32);
    return u;
}

int main()
{
    CVerusHash::init();
    CVerusHashV2::init();

    // Mask algebra: attempt bits (32..39) + retry entropy (40..127) must
    // exactly tile the legacy entropy field (bits 32..127), disjoint.
    CHECK((CPOSNonce::attemptMask | CPOSNonce::retryEntropyMask) == CPOSNonce::entropyMask);
    CHECK((CPOSNonce::attemptMask & CPOSNonce::retryEntropyMask) == arith_uint256(0));
    CHECK((CPOSNonce::attemptMask | CPOSNonce::retryEntropyMask | CPOSNonce::posDiffMask) ==
          (CPOSNonce::entropyMask | CPOSNonce::posDiffMask));

    // Attempt get/set round-trip over the full 8-bit field.
    for (uint32_t a = 0; a < 256; a++)
    {
        CPOSNonce n;
        n.SetStakeAttempt(a);
        CHECK(n.GetStakeAttempt() == a);
    }
    {
        CPOSNonce n;
        n.SetStakeAttempt(0);
        CHECK(n.IsNull());
        n.SetStakeAttempt(255);
        CHECK(n.GetStakeAttempt() == 255);
        CHECK(!n.IsNull());
        n.SetStakeAttempt(300); // masked to 8 bits
        CHECK(n.GetStakeAttempt() == (300 & 0xff));
    }

    uint256 pastHash = Repeat(0x11);
    uint256 txid = Repeat(0x22);
    uint32_t nBits = 0x1e0de932; // real testnet-shaped target

    // Legacy frozen vectors (pre-change code, fRetryRules=false must
    // reproduce them bit-for-bit on the NEW code).
    const char *legacyTarget[2] = {
        "59cd82bc3da4c6eb476fbcb8b49c435c0000000000000000000000001e0de932",
        "94009122b65d1554165771a9b5be0ca00000000000000000000000001e0de932",
    };
    const char *legacyEntropy[2] = {
        "8d10b9d4eab13fa632494c4193d844d79eef5aa42ecc9eb981beb1e41e0de932",
        "b36527511b4df687193e5a407d3c6a912eab7f6f92e13734b03f4f8d1e0de932",
    };

    for (int v = 0; v < 2; v++)
    {
        uint32_t ver = v ? CPOSNonce::LUCKY_V2 : CPOSNonce::LUCKY_V1;
        CPOSNonce n;
        n.SetPOSTarget(nBits, ver);
        CHECK(n.GetHex() == legacyTarget[v]);
        n.SetPOSEntropy(pastHash, txid, 3, ver, false);
        CHECK(n.GetHex() == legacyEntropy[v]);
        CHECK(n.CheckPOSEntropy(pastHash, txid, 3, ver, false));
        CHECK(n.IsPOSNonce(ver));
        CHECK(n.GetPOSTarget() == nBits);
        // Legacy path ignores attempt bits set beforehand (proves the old
        // rule never saw the new field).
        n.SetStakeAttempt(200);
        n.SetPOSEntropy(pastHash, txid, 3, ver, false);
        CHECK(n.GetHex() == legacyEntropy[v]);
    }

    // New rule: attempt changes the derivation (the fork point — attempt 0
    // under the new rule differs from legacy on purpose).
    for (int v = 0; v < 2; v++)
    {
        uint32_t ver = v ? CPOSNonce::LUCKY_V2 : CPOSNonce::LUCKY_V1;
        CPOSNonce base;
        base.SetPOSTarget(nBits, ver);
        base.SetPOSEntropy(pastHash, txid, 3, ver, true); // attempt defaults 0
        CHECK(base.GetStakeAttempt() == 0);
        CHECK(std::string(base.GetHex()) != std::string(v ? legacyEntropy[1] : legacyEntropy[0]));
        CHECK(base.CheckPOSEntropy(pastHash, txid, 3, ver, true));
        CHECK(base.IsPOSNonce(ver));

        // Attempt sweep: distinct nonces, all verify, target preserved.
        uint256 seen[4];
        uint32_t attempts[4] = {0, 1, 63, 255};
        for (int i = 0; i < 4; i++)
        {
            CPOSNonce n;
            n.SetPOSTarget(nBits, ver);
            n.SetStakeAttempt(attempts[i]);
            CHECK(n.GetStakeAttempt() == attempts[i]);
            n.SetPOSEntropy(pastHash, txid, 3, ver, true);
            CHECK(n.CheckPOSEntropy(pastHash, txid, 3, ver, true));
            CHECK(n.IsPOSNonce(ver));
            CHECK(n.GetPOSTarget() == nBits);
            CHECK(n.GetStakeAttempt() == attempts[i]);
            seen[i] = (uint256)n;
            for (int j = 0; j < i; j++)
            {
                CHECK(seen[i] != seen[j]);
            }
            // Cross-check: legacy verification of a new-rule nonce fails
            // (old nodes reject attempt>0 blocks - the clean fork).
            if (attempts[i] != 0)
            {
                CHECK(!n.CheckPOSEntropy(pastHash, txid, 3, ver, false));
            }
        }
    }

    if (failures == 0)
    {
        printf("POS KAT GATE PASSED (0 failures)\n");
        return 0;
    }
    printf("POS KAT GATE FAILED (%d failures)\n", failures);
    return 1;
}
