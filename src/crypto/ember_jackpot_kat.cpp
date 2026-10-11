// KAT gate for the jackpot money rules (doc 06 §6.2): frozen vectors from
// the Rust reference (`lm-rewards::reserve` tests). Build & run standalone:
//   g++ -O2 -std=c++11 -I<repo>/src <repo>/src/crypto/ember_jackpot_kat.cpp -o /tmp/jk && /tmp/jk
// Any mismatch exits non-zero.
#include "consensus/jackpot.h"

#include <stdio.h>

static int failures = 0;

#define CHECK(cond) do { if (!(cond)) { failures++; printf("FAIL line %d: %s\n", __LINE__, #cond); } else { printf("ok   line %d\n", __LINE__); } } while (0)

int main()
{
    using namespace jackpot;

    // levy: 5% floored (doc example R=100,F=2 -> 5.1 decimals, 5 floored)
    CHECK(Levy(100, 2) == 5);
    CHECK(Levy(100000000ULL, 2000000ULL) == 5100000ULL);
    CHECK(Levy(0, 0) == 0);

    // normal block grows the reserve; conservation holds
    {
        Payout p = ApplyBlock(0, 100000000ULL, 2000000ULL, false);
        CHECK(p.miner == 96900000ULL);
        CHECK(p.bonus == 0);
        CHECK(p.to_reserve == 5100000ULL);
        CHECK(p.to_league == 0);
        CHECK(p.reserve == 5100000ULL);
        CHECK(p.miner + (p.reserve - 0) + p.to_league == 102000000ULL);
    }

    // warm-up: reserve starts at 0, first jackpot pays only its own levy
    {
        Payout p = ApplyBlock(0, 100, 2, true);
        CHECK(p.to_reserve == 5);
        CHECK(p.bonus == 5);
        CHECK(p.miner == 102);
        CHECK(p.reserve == 0);
    }

    // full bonus at a healthy reserve
    {
        Payout p = ApplyBlock(5000, 100, 0, true);
        CHECK(p.bonus == 500);
        CHECK(p.miner == 95 + 500);
        CHECK(p.reserve == 4500);
    }

    // cap overflow feeds the league pool; conservation still exact
    // (R=100, F=2: normal = 97, bonus = 500, miner = 597)
    {
        Payout p = ApplyBlock(5000, 100, 2, true); // cap = 5000, already full
        CHECK(p.to_reserve == 0);
        CHECK(p.to_league == 5);
        CHECK(p.bonus == 500);
        CHECK(p.miner == 597);
        CHECK(p.reserve == 4500);
        uint64_t before = 5000;
        CHECK(p.miner + (p.reserve >= before ? p.reserve - before : 0) + p.to_league - (before > p.reserve ? before - p.reserve : 0) == 102);
    }

    // every-block conservation sweep: miner + dReserve + league == R + F
    {
        struct Case { uint64_t r, b, f; bool j; };
        Case cases[] = {
            {0, 100, 2, false}, {0, 100, 2, true}, {7, 100, 2, false},
            {7, 100, 2, true}, {5000, 100, 2, false}, {5000, 100, 2, true},
            {0, 0, 1000, true}, {1000000, 12500000000ULL, 500000, true},
        };
        for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++)
        {
            Payout p = ApplyBlock(cases[k].r, cases[k].b, cases[k].f, cases[k].j);
            __uint128_t inflow = (__uint128_t)cases[k].b + cases[k].f;
            __uint128_t outflow = (__uint128_t)p.miner + p.reserve + p.to_league - cases[k].r;
            if (outflow != inflow)
            {
                failures++;
                printf("FAIL conservation case %zu\n", k);
            }
        }
        printf("ok   conservation sweep\n");
    }

    printf("\n%s (%d failures)\n", failures ? "JACKPOT KAT GATE FAILED" : "JACKPOT KAT GATE PASSED", failures);
    return failures ? 1 : 0;
}
