// Copyright (c) 2026 Lucky Lode developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// CEmberHash — the fork's block-header PoW digest (LuckyHash v1, doc 05
// rev 1.0 + Addendum A). Normative reference: Rust `lm-pow` crate; the KAT
// runner (`ember_kat.cpp`) must agree with it byte-for-byte.
//
//   seed = BLAKE3(header_bytes || nonce_le64)
//   salt = "LMv1" || height_le64
//   mem  = Argon2id(seed, salt, AD="lowmine-pow/v1", m=1024, t=3, p=1, out=32)
//   out  = BLAKE3(mem || seed)                    // compared big-endian

#ifndef LUCKYLODE_EMBER_HASH_H
#define LUCKYLODE_EMBER_HASH_H

#include <stdint.h>
#include <stddef.h>

namespace ember
{
    static const uint32_t M_COST = 1024;              // KiB (1 MiB)
    static const uint32_t T_COST = 3;                 // passes
    static const uint32_t P_COST = 1;                 // lanes per instance
    static const size_t OUT_LEN = 32;
    static const char SALT_PREFIX[4] = {'L', 'M', 'v', '1'};
    static const char ASSOCIATED_DATA[] = "lowmine-pow/v1";

    /** Full evaluation: writes 32-byte seed, mem, out stages. */
    bool HashFull(uint8_t seed[32], uint8_t mem[32], uint8_t out[32],
                  const void *headerBytes, size_t headerLen,
                  uint64_t nonce, uint64_t height);

    /** Final digest only (the hot path for mining and verification). */
    bool Hash(uint8_t out[32], const void *headerBytes, size_t headerLen,
              uint64_t nonce, uint64_t height);
}

#endif // LUCKYLODE_EMBER_HASH_H
