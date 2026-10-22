// Copyright (c) 2018 Michael Toutonghi
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "hash.h"
#include "nonce.h"
#include <cstring>

extern char ASSETCHAINS_SYMBOL[65];

arith_uint256 CPOSNonce::entropyMask = UintToArith256(uint256S("00000000000000000000000000000000ffffffffffffffffffffffff00000000"));
arith_uint256 CPOSNonce::posDiffMask = UintToArith256(uint256S("00000000000000000000000000000000000000000000000000000000ffffffff"));
// Lucky Lode solo-PoS liveness (internal/22): attempt counter lives in
// nonce bits 32..39; retry entropy occupies bits 40..127. Invariant (KAT
// pinned): attemptMask | retryEntropyMask == entropyMask (disjoint).
arith_uint256 CPOSNonce::attemptMask = UintToArith256(uint256S("000000000000000000000000000000000000000000000000000000ff00000000"));
arith_uint256 CPOSNonce::retryEntropyMask = UintToArith256(uint256S("00000000000000000000000000000000ffffffffffffffffffffff0000000000"));

bool CPOSNonce::NewPOSActive(int32_t height)
{
    if (_IsVerusMainnetActive() && (height < (96480 + 100)))
        return false;
    else
        return true;
}

bool CPOSNonce::NewNonceActive(int32_t height)
{
    if (_IsVerusMainnetActive() && (height < 96480))
        return false;
    else
        return true;
}

void CPOSNonce::SetPOSEntropy(const uint256 &pastHash, uint256 txid, int32_t voutNum, uint32_t version, bool fRetryRules)
{
    // The attempt counter rides in the nonce itself (bits 32..39, written
    // by the staker via SetStakeAttempt before this call).
    uint32_t attempt = fRetryRules ? GetStakeAttempt() : 0;
    if (version == VERUS_V2)
    {
        // get low 96 bits of past hash and put it in top 96 bits of low 128 bits of nonce
        CVerusHashV2Writer hashWriter = CVerusHashV2Writer(SER_GETHASH, PROTOCOL_VERSION);

        // first hash the pastHash, txid, and voutNum, to create a combined 96 bits, which will be used in the nonce
        hashWriter << pastHash;
        hashWriter << txid;
        hashWriter << voutNum;

        arith_uint256 arNonce;
        if (fRetryRules)
        {
            // Solo-PoS liveness: the attempt is mixed into the entropy and
            // carried in bits 32..39; retry entropy occupies bits 40..127.
            // Target nBits (bits 0..31) are preserved, not re-derived.
            hashWriter << attempt;
            arNonce = (UintToArith256(*this) & (posDiffMask | attemptMask)) |
                (UintToArith256(hashWriter.GetHash()) & retryEntropyMask);
        }
        else
        {
            // Legacy derivation, bit-identical to pre-change behavior.
            arNonce = (UintToArith256(*this) & posDiffMask) |
                (UintToArith256(hashWriter.GetHash()) & entropyMask);
        }

        // printf("before %s\n", ArithToUint256(arNonce).GetHex().c_str());

        hashWriter.Reset();
        hashWriter << ArithToUint256(arNonce);

        *this = CPOSNonce(ArithToUint256((UintToArith256(hashWriter.GetHash()) << 128) | arNonce));

        // printf("after  %s\n", this->GetHex().c_str());
    }
    else
    {
        // get low 96 bits of past hash and put it in top 96 bits of low 128 bits of nonce
        CVerusHashWriter hashWriter = CVerusHashWriter(SER_GETHASH, PROTOCOL_VERSION);

        // first hash the pastHash, txid, and voutNum, to create a combined 96 bits, which will be used in the nonce
        hashWriter << pastHash;
        hashWriter << txid;
        hashWriter << voutNum;

        arith_uint256 arNonce;
        if (fRetryRules)
        {
            hashWriter << attempt;
            arNonce = (UintToArith256(*this) & (posDiffMask | attemptMask)) |
                (UintToArith256(hashWriter.GetHash()) & retryEntropyMask);
        }
        else
        {
            // Legacy derivation, bit-identical to pre-change behavior.
            arNonce = (UintToArith256(*this) & posDiffMask) |
                (UintToArith256(hashWriter.GetHash()) & entropyMask);
        }

        // printf("before %s\n", ArithToUint256(arNonce).GetHex().c_str());

        hashWriter.Reset();
        hashWriter << ArithToUint256(arNonce);

        *this = CPOSNonce(ArithToUint256((UintToArith256(hashWriter.GetHash()) << 128) | arNonce));

        // printf("after  %s\n", this->GetHex().c_str());
    }
}

bool CPOSNonce::CheckPOSEntropy(const uint256 &pastHash, uint256 txid, int32_t voutNum, uint32_t version, bool fRetryRules)
{
    // The attempt counter rides in the nonce itself (bits 32..39); the
    // validator re-derives with the same attempt the staker used.
    uint32_t attempt = fRetryRules ? GetStakeAttempt() : 0;
    if (version == VERUS_V2)
    {
        // get low 96 bits of past hash and put it in top 96 bits of low 128 bits of nonce
        CVerusHashV2Writer hashWriter = CVerusHashV2Writer(SER_GETHASH, PROTOCOL_VERSION);

        // first hash the pastHash, txid, and voutNum, to create a combined 96 bits, which will be used in the nonce
        hashWriter << pastHash;
        hashWriter << txid;
        hashWriter << voutNum;

        arith_uint256 arNonce;
        if (fRetryRules)
        {
            hashWriter << attempt;
            arNonce = (UintToArith256(*this) & (posDiffMask | attemptMask)) |
                (UintToArith256(hashWriter.GetHash()) & retryEntropyMask);
        }
        else
        {
            // Legacy check, bit-identical to pre-change behavior.
            arNonce = (UintToArith256(*this) & posDiffMask) |
                (UintToArith256(hashWriter.GetHash()) & entropyMask);
        }

        hashWriter.Reset();
        hashWriter << ArithToUint256(arNonce);

        return UintToArith256(*this) == (UintToArith256(hashWriter.GetHash()) << 128 | arNonce);
    }
    else
    {
        // get low 96 bits of past hash and put it in top 96 bits of low 128 bits of nonce
        CVerusHashWriter hashWriter = CVerusHashWriter(SER_GETHASH, PROTOCOL_VERSION);

        // first hash the pastHash, txid, and voutNum, to create a combined 96 bits, which will be used in the nonce
        hashWriter << pastHash;
        hashWriter << txid;
        hashWriter << voutNum;

        arith_uint256 arNonce;
        if (fRetryRules)
        {
            hashWriter << attempt;
            arNonce = (UintToArith256(*this) & (posDiffMask | attemptMask)) |
                (UintToArith256(hashWriter.GetHash()) & retryEntropyMask);
        }
        else
        {
            // Legacy check, bit-identical to pre-change behavior.
            arNonce = (UintToArith256(*this) & posDiffMask) |
                (UintToArith256(hashWriter.GetHash()) & entropyMask);
        }

        hashWriter.Reset();
        hashWriter << ArithToUint256(arNonce);

        return UintToArith256(*this) == (UintToArith256(hashWriter.GetHash()) << 128 | arNonce);
    }
}

