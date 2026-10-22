// Copyright (c) 2018 Michael Toutonghi
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_NONCE_H
#define BITCOIN_PRIMITIVES_NONCE_H

#include "serialize.h"
#include "uint256.h"
#include "arith_uint256.h"
#include "hash.h"


/** For POS blocks, the nNonce of a block header holds the entropy source for the POS contest
 * in the latest VerusHash protocol
 * */
class CPOSNonce : public uint256
{
public:
    static const int32_t LUCKY_V1=4;
    static const int32_t LUCKY_V2=0x00010004;

    static bool NewPOSActive(int32_t height);
    static bool NewNonceActive(int32_t height);

    static arith_uint256 entropyMask;
    static arith_uint256 posDiffMask;
    // Lucky Lode solo-PoS liveness (internal/22): bits 32..39 of the low
    // 128 nonce bits carry a bounded stake attempt counter, letting the
    // staker retry a draw within one height. 0 = legacy single attempt.
    // The retry entropy occupies bits 40..127 (see retryEntropyMask).
    static arith_uint256 attemptMask;
    static arith_uint256 retryEntropyMask;

    uint32_t GetStakeAttempt() const
    {
        return (uint32_t)((UintToArith256(*this) & attemptMask) >> 32).GetLow64();
    }

    void SetStakeAttempt(uint32_t attempt)
    {
        arith_uint256 arNonce = UintToArith256(*this);
        arNonce &= ~attemptMask;
        arNonce |= arith_uint256(attempt & 0xff) << 32;
        (uint256 &)(*this) = ArithToUint256(arNonce);
    }

    CPOSNonce() : uint256() { }
    CPOSNonce(const base_blob<256> &b) : uint256(b) { }
    CPOSNonce(const std::vector<unsigned char> &vch) : uint256(vch) { }

    int32_t GetPOSTarget() const
    {
        uint32_t nBits = 0;

        for (const unsigned char *p = begin() + 3; p >= begin(); p--)
        {
            nBits <<= 8;
            nBits += *p;
        }
        return nBits;
    }

    bool IsPOSNonce(uint32_t version=LUCKY_V1) const
    {
        arith_uint256 arNonce = UintToArith256(*this);
        arith_uint256 tmpNonce = ((arNonce << 128) >> 128);
        if (version == LUCKY_V2)
        {
            CVerusHashV2Writer hashWriter = CVerusHashV2Writer(SER_GETHASH, PROTOCOL_VERSION);
            hashWriter << ArithToUint256(tmpNonce);
            return (*this == ArithToUint256(UintToArith256(hashWriter.GetHash()) << 128 | tmpNonce));
        }
        else
        {
            CVerusHashWriter hashWriter = CVerusHashWriter(SER_GETHASH, PROTOCOL_VERSION);
            hashWriter << ArithToUint256(tmpNonce);
            return (*this == ArithToUint256(UintToArith256(hashWriter.GetHash()) << 128 | tmpNonce));
        }
    }

    void SetPOSTarget(uint32_t nBits, uint32_t version=LUCKY_V1)
    {
        arith_uint256 arNonce = (UintToArith256(*this) & entropyMask) | nBits;

        if (version == LUCKY_V2)
        {
            CVerusHashV2Writer hashWriter = CVerusHashV2Writer(SER_GETHASH, PROTOCOL_VERSION);
            hashWriter << ArithToUint256(arNonce);
            (uint256 &)(*this) = ArithToUint256(UintToArith256(hashWriter.GetHash()) << 128 | arNonce);
        }
        else
        {
            CVerusHashWriter hashWriter = CVerusHashWriter(SER_GETHASH, PROTOCOL_VERSION);
            hashWriter << ArithToUint256(arNonce);
            (uint256 &)(*this) = ArithToUint256(UintToArith256(hashWriter.GetHash()) << 128 | arNonce);
        }
    }

    // fRetryRules selects the post-activation derivation (attempt mixed
    // into the entropy, attempt bits preserved). No default: every caller
    // must state which rule it wants, so a missed call site fails to
    // compile instead of silently validating under the wrong rule.
    void SetPOSEntropy(const uint256 &pastHash, uint256 txid, int32_t voutNum, uint32_t version, bool fRetryRules);
    bool CheckPOSEntropy(const uint256 &pastHash, uint256 txid, int32_t voutNum, uint32_t version, bool fRetryRules);
};

#endif // BITCOIN_PRIMITIVES_NONCE_H
