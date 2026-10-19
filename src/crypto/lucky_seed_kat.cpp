// KAT gate for the seed-fund money rules (internal/20): frozen vectors
// mirrored in Rust (`lm-rewards::seed` tests). Build & run standalone:
//   g++ -O2 -std=c++11 -I<repo>/src <repo>/src/crypto/lucky_seed_kat.cpp -o /tmp/seed && /tmp/seed
// Any mismatch exits non-zero.
#include "consensus/lucky_seed.h"

#include <stdio.h>

static int failures = 0;

#define CHECK(cond) do { if (!(cond)) { failures++; printf("FAIL line %d: %s\n", __LINE__, #cond); } else { printf("ok   line %d\n", __LINE__); } } while (0)

using namespace lucky_seed;

int main()
{
    // Seeds are the documented testnet constants.
    CHECK(FAUCET_SEED == 10000000000000ULL);
    CHECK(DEV_SEED == 5000000000000ULL);
    CHECK(FAUCET_CAP == 100000000000ULL);
    CHECK(DEV_CAP == 10000000000ULL);
    CHECK(DEV_EPOCH == 100);

    // Allowances: faucet every block, dev only on epoch heights, both
    // bounded by their reserves; unpinned legs are inert.
    CHECK(FaucetAllowance(FAUCET_SEED, true) == FAUCET_CAP);
    CHECK(FaucetAllowance(500, true) == 500);
    CHECK(FaucetAllowance(FAUCET_SEED, false) == 0);
    CHECK(FaucetAllowance(0, true) == 0);
    CHECK(DevAllowance(DEV_SEED, 100, true) == DEV_CAP);
    CHECK(DevAllowance(DEV_SEED, 200, true) == DEV_CAP);
    CHECK(DevAllowance(DEV_SEED, 99, true) == 0);
    CHECK(DevAllowance(DEV_SEED, 101, true) == 0);
    CHECK(DevAllowance(50, 300, true) == 50);
    CHECK(DevAllowance(DEV_SEED, 100, false) == 0);
    CHECK(DevAllowance(0, 100, true) == 0);

    // Exact claims debit actuals; conservation holds to the satoshi.
    {
        SeedPayout p = ApplySeedBlock(FAUCET_SEED, DEV_SEED, 100, 1000, 50, true, true);
        CHECK(p.ok);
        CHECK(p.faucet_claimed == 1000 && p.dev_claimed == 50);
        CHECK(p.faucet + 1000 == FAUCET_SEED && p.dev + 50 == DEV_SEED);
    }
    // Zero claims leave full reserves (the common block).
    {
        SeedPayout p = ApplySeedBlock(FAUCET_SEED, DEV_SEED, 101, 0, 0, true, true);
        CHECK(p.ok);
        CHECK(p.faucet == FAUCET_SEED && p.dev == DEV_SEED);
    }
    // Over-allowance claims fail closed (no vaporize, no clamp-and-pay).
    {
        SeedPayout p = ApplySeedBlock(1000, 1000, 200, 1001, 0, true, true);
        CHECK(!p.ok);
        CHECK(p.faucet == 1000 && p.dev == 1000);
    }
    {
        SeedPayout p = ApplySeedBlock(1000, 1000, 200, 0, 1001, true, true);
        CHECK(!p.ok);
    }
    // Unpinned legs cannot pay even with full reserves.
    {
        SeedPayout p = ApplySeedBlock(FAUCET_SEED, DEV_SEED, 300, 1, 1, false, false);
        CHECK(!p.ok);
        CHECK(p.faucet == FAUCET_SEED && p.dev == DEV_SEED);
    }
    // Explicit epoch threading (regtest override parity): the epoch the
    // caller passes is the epoch that gates, pinned by vector.
    {
        SeedPayout p = ApplySeedBlock(DEV_SEED, DEV_SEED, 6, 0, DEV_CAP, true, true, 5);
        CHECK(!p.ok); // 6 % 5 != 0 under epoch 5
        SeedPayout q = ApplySeedBlock(DEV_SEED, DEV_SEED, 10, 0, DEV_CAP, true, true, 5);
        CHECK(q.ok && q.dev == DEV_SEED - DEV_CAP);
    }
    // Dev claims off-epoch fail even within cap.
    {
        SeedPayout p = ApplySeedBlock(FAUCET_SEED, DEV_SEED, 301, 0, 10, true, true);
        CHECK(!p.ok);
        CHECK(p.dev == DEV_SEED);
    }

    if (failures == 0)
    {
        printf("\nSEED KAT GATE PASSED (0 failures)\n");
        return 0;
    }
    printf("\nSEED KAT GATE FAILED (%d failures)\n", failures);
    return 1;
}
