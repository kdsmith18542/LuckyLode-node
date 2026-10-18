// KAT gate for CLuckyHash: asserts doc 05 §5.4 vectors + Addendum A vector A1.
// Build & run (from repo root):
//   verus/src/crypto/lucky_kat.sh
// Any mismatch exits non-zero — this gate must pass before any node build.

#include "crypto/lucky_hash.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int failures = 0;

static int fromhex(const char *hex, uint8_t *out)
{
    size_t n = strlen(hex);
    if (n % 2) return -1;
    for (size_t i = 0; i < n / 2; i++)
    {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return (int)(n / 2);
}

static void check(const char *name, const char *stage,
                  const uint8_t got[32], const char *want_hex)
{
    uint8_t want[32];
    fromhex(want_hex, want);
    if (memcmp(got, want, 32) != 0)
    {
        failures++;
        printf("FAIL %s %s\n  got  ", name, stage);
        for (int i = 0; i < 32; i++) printf("%02x", got[i]);
        printf("\n  want %s\n", want_hex);
    }
    else
    {
        printf("ok   %s %s\n", name, stage);
    }
}

static void run(const char *name, const uint8_t *header, size_t hlen,
                uint64_t nonce, uint64_t height,
                const char *seed_hex, const char *mem_hex, const char *out_hex)
{
    uint8_t seed[32], mem[32], out[32];
    if (!ember::HashFull(seed, mem, out, header, hlen, nonce, height))
    {
        failures++;
        printf("FAIL %s: HashFull returned false\n", name);
        return;
    }
    check(name, "seed", seed, seed_hex);
    check(name, "mem ", mem, mem_hex);
    check(name, "out ", out, out_hex);
}

int main()
{
    // §5.4 vectors: 80-byte header 0x00..0x4F
    uint8_t header_v[80];
    for (int i = 0; i < 80; i++) header_v[i] = (uint8_t)i;

    run("V1 (nonce=0,height=1)       ", header_v, 80, 0, 1,
        "c0d0cb7a3009c163ef6d92fa2626158077777553b794c8fa6f3d29a7c7f26e86",
        "446765c0245c7d3da7185456343055971444c45dd90b015d4fd7b3c6262a2b99",
        "ff0d88d9bf49d0d5c47a78b9a8f5478640359c4da7e73ee23973d6c338e2ca6e");

    run("V2 (nonce=1,height=1)       ", header_v, 80, 1, 1,
        "88c16e6cb829970c72730f29ccad9448b425727340f492a47885357f95c6d549",
        "3924a6a0bfefe126c881fc7764794d6f45b992f5f22d33b2fd339af5bf405dbe",
        "9c50add868c939b69096279e08387ae4593524d095cdd83a4ef5ea09908c67fd");

    run("V3 (nonce=u64MAX,h=12345)   ", header_v, 80, 0xFFFFFFFFFFFFFFFFULL, 12345,
        "ee822cda19fa6523becfdaa72ac7a8581ac9316b340f9ca7648c7c8b45777cef",
        "48063374526971416c8c7d8f7b4e4ab815d4e4c6a4956024d2c3b459817a2791",
        "335c53228b27bfd9b867774886df4226246727913d6ed8a7933c019b93cf24a0");

    // Addendum A vector A1: canonical 109-byte fork header (empty solution)
    uint8_t fork_header[109];
    size_t o = 0;
    fork_header[o++] = 0x04; fork_header[o++] = 0x00; // nVersion LE 0x00010004
    fork_header[o++] = 0x01; fork_header[o++] = 0x00;
    memset(fork_header + o, 0x11, 32); o += 32;       // hashPrevBlock
    memset(fork_header + o, 0x22, 32); o += 32;       // hashMerkleRoot
    memset(fork_header + o, 0x33, 32); o += 32;       // hashFinalSaplingRoot
    fork_header[o++] = 42; fork_header[o++] = 0;      // nTime LE 42
    fork_header[o++] = 0; fork_header[o++] = 0;
    fork_header[o++] = 0xff; fork_header[o++] = 0xff; // nBits LE 0x1d00ffff
    fork_header[o++] = 0x00; fork_header[o++] = 0x1d;
    fork_header[o++] = 0x00;                          // CompactSize(0) solution

    run("A1 (nonce=7,height=100)     ", fork_header, o, 7, 100,
        "df2f1c48bdc8f58fb4f7247b5c4fe2257011c8842e3859fc245cd654a8030619",
        "d68a955d887a8e4d4c40d34ec2bc4fbdf8e8f4135e0e856dd6d6a2f957b8110d",
        "e491f172e0d0adcb161fb264413292bfca631fff8c390218b6cabdac6f452131");

    printf("\n%s (%d failures)\n", failures ? "KAT GATE FAILED" : "KAT GATE PASSED", failures);
    return failures ? 1 : 0;
}
