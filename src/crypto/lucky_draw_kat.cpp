// KAT gate for the pre-committable draw trigger (doc 06 rev 1.2,
//): digest = SHA256D(parent hash || height LE32),
// jackpot < floor(2^256/odds), tier = digest mod 100.
// Vectors frozen 2026-10-14 (generated independently with Python hashlib).
// Build & run: verus/src/crypto/lucky_kat.sh (runs all gates).

#include "consensus/lucky_draw.h"
#include "uint256.h"

// Stand-in for utilstrencodings' HexDigit: uint256.cpp (linked for base_uint
// Roundtrip support) references it via base_blob::SetHex, which this gate
// never exercises. Kept trivial and local to the standalone KAT runner.
signed char HexDigit(char c)
{
    if (c >= '0' && c <= '9') return (signed char)(c - '0');
    if (c >= 'a' && c <= 'f') return (signed char)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (signed char)(c - 'A' + 10);
    return -1;
}

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
    using namespace lucky_draw;

    // Vector 1: prev = 0x11 * 32, height 100 (plain height, mid-space).
    uint256 p1 = Repeat(0x11);
    uint256 d1 = Digest(p1, 100);
    CHECK(d1.GetHex() == "3086b122f52f0c27064e330f31e1ebf04164cf07be2b1dcfc0ed70647b7bd63e");
    CHECK(Tier(d1) == 66);
    CHECK(!Jackpot(d1, 100));
    CHECK(!PotEvent(d1, 1000));

    // Vector 2: prev = bytes 0..31, height 12345 (non-trivial bytes + LE).
    uint256 p2;
    for (int i = 0; i < 32; i++) p2.begin()[i] = (unsigned char)i;
    uint256 d2 = Digest(p2, 12345);
    CHECK(d2.GetHex() == "de233f46bbab5baf7e4e6183469038e219e360be104d018f4e0691ad0f70e3a7");
    CHECK(Tier(d2) == 15);
    CHECK(!Jackpot(d2, 100));

    // Vector 3: prev = 0x22 * 32, height 108 — a jackpot height (found by
    // search; digest < 2^256/100).
    uint256 p3 = Repeat(0x22);
    uint256 d3 = Digest(p3, 108);
    CHECK(d3.GetHex() == "00cc6dc915f24af9f3f9d1a935d39c7ca135e630a653d521ec0ca2ad688b0c03");
    CHECK(Jackpot(d3, 100));
    CHECK(!PotEvent(d3, 1000));
    CHECK(Tier(d3) == 87);

    // Vector 4: prev = 0x22 * 32, height 440 — a pot event (and therefore
    // also a jackpot: the pot band is nested inside the jackpot band).
    uint256 d4 = Digest(p3, 440);
    CHECK(d4.GetHex() == "0010263248e4e556f3e539286eb1303ce51ef2548a376bb79033fd032da75dfe");
    CHECK(PotEvent(d4, 1000));
    CHECK(Jackpot(d4, 100));
    CHECK(Tier(d4) == 66);

    // Boundaries: strict less-than at floor(2^256/divisor).
    {
        arith_uint256 t = Threshold(100);
        CHECK(Jackpot(ArithToUint256(t - 1), 100));
        CHECK(!Jackpot(ArithToUint256(t), 100));
        CHECK(!Jackpot(ArithToUint256(t + 1), 100));
    }
    {
        arith_uint256 t = Threshold(1000);
        CHECK(PotEvent(ArithToUint256(t - 1), 1000));
        CHECK(!PotEvent(ArithToUint256(t), 1000));
    }

    // Regtest overrides: divisor 1 = every height (zero digest always
    // passes; the 2^-256 max-digest edge is out of scope by construction).
    CHECK(Jackpot(uint256(), 1));
    CHECK(PotEvent(uint256(), 1));

    // Thresholds are exactly floor(2^256 / divisor), nested.
    {
        arith_uint256 mx = ~arith_uint256(0);
        arith_uint256 t100 = Threshold(100);
        arith_uint256 t1000 = Threshold(1000);
        CHECK(t100 == mx / 100);
        CHECK(t1000 == mx / 1000);
        CHECK(t1000 < t100);
    }

    if (failures == 0)
        printf("\nDRAW KAT GATE PASSED (0 failures)\n");
    else
        printf("\nDRAW KAT GATE FAILED (%d failures)\n", failures);
    return failures == 0 ? 0 : 1;
}
