// (C) 2026 Lowmine developers — MIT, see COPYING.
//
// EmberHash v1 for the Lowmine fork: see ember_hash.h. Vendored deps:
// BLAKE3 (CC0, crypto/blake3/) and Argon2 reference (CC0/Apache-2.0,
// crypto/argon2/).

#include "crypto/ember_hash.h"

#include "crypto/blake3/blake3.h"
#include "crypto/argon2/argon2.h"

#include <string.h>

namespace ember
{

static void blake3_hash(uint8_t out[32], const void *data, size_t len)
{
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, data, len);
    blake3_hasher_finalize(&h, out, 32);
}

bool HashFull(uint8_t seed[32], uint8_t mem[32], uint8_t out[32],
              const void *headerBytes, size_t headerLen,
              uint64_t nonce, uint64_t height)
{
    // seed = BLAKE3(header || nonce_le64)
    uint8_t nonce_le[8];
    for (int i = 0; i < 8; i++) nonce_le[i] = (uint8_t)(nonce >> (8 * i));
    {
        blake3_hasher h;
        blake3_hasher_init(&h);
        blake3_hasher_update(&h, headerBytes, headerLen);
        blake3_hasher_update(&h, nonce_le, 8);
        blake3_hasher_finalize(&h, seed, 32);
    }

    // salt = "LMv1" || height_le64
    uint8_t salt[12];
    memcpy(salt, SALT_PREFIX, 4);
    for (int i = 0; i < 8; i++) salt[4 + i] = (uint8_t)(height >> (8 * i));

    // mem = Argon2id(seed, salt, AD, m=1024, t=3, p=1, out=32)
    {
        uint32_t adlen = (uint32_t)(sizeof(ASSOCIATED_DATA) - 1);
        argon2_context ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.out = mem;
        ctx.outlen = (uint32_t)OUT_LEN;
        ctx.pwd = (uint8_t *)seed;          // password = seed
        ctx.pwdlen = 32;
        ctx.salt = salt;
        ctx.saltlen = sizeof(salt);
        ctx.secret = NULL;
        ctx.secretlen = 0;
        ctx.ad = (uint8_t *)ASSOCIATED_DATA; // associated data
        ctx.adlen = adlen;
        ctx.t_cost = T_COST;
        ctx.m_cost = M_COST;
        ctx.lanes = P_COST;
        ctx.threads = P_COST;
        ctx.allocate_cbk = NULL;
        ctx.free_cbk = NULL;
        ctx.flags = ARGON2_DEFAULT_FLAGS;
        ctx.version = ARGON2_VERSION_13;    // 0x13, matches lm-pow
        int rc = argon2_ctx(&ctx, Argon2_id);
        if (rc != ARGON2_OK)
        {
            return false;
        }
    }

    // out = BLAKE3(mem || seed)
    {
        blake3_hasher h;
        blake3_hasher_init(&h);
        blake3_hasher_update(&h, mem, 32);
        blake3_hasher_update(&h, seed, 32);
        blake3_hasher_finalize(&h, out, 32);
    }
    return true;
}

bool Hash(uint8_t out[32], const void *headerBytes, size_t headerLen,
          uint64_t nonce, uint64_t height)
{
    uint8_t seed[32], mem[32];
    return HashFull(seed, mem, out, headerBytes, headerLen, nonce, height);
}

} // namespace ember
