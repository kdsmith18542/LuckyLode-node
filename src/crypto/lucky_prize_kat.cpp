// KAT gate 7 for the Prize Fund money rules (doc 06 §6.7): frozen
// vectors mirrored in Rust (`lm-rewards::prize` tests). Build & run
// standalone:
//   g++ -O2 -std=c++11 -I<repo>/src <repo>/src/crypto/lucky_prize_kat.cpp -o /tmp/prize && /tmp/prize
// Any mismatch exits non-zero.
#include "consensus/lucky_prize.h"

#include <stdio.h>

static int failures = 0;

#define CHECK(cond) do { if (!(cond)) { failures++; printf("FAIL line %d: %s\n", __LINE__, #cond); } else { printf("ok   line %d\n", __LINE__); } } while (0)

using namespace lucky_prize;

int main()
{
    // Seed + slice are the frozen spec constants (doc 06 §6.7).
    CHECK(PRIZE_SEED == 100000000000ULL);
    CHECK(PRIZE_SLICE_BPS == 1000);

    // Credit: saturating accumulation.
    CHECK(Credit(0, 0) == 0);
    CHECK(Credit(100, 25) == 125);
    CHECK(Credit(~uint64_t(0) - 1, 5) == ~uint64_t(0));

    // Trailing inflow: rise + claims; never below zero, saturating.
    CHECK(TrailingInflow(150, 100, 0) == 50);
    CHECK(TrailingInflow(100, 150, 60) == 10);   // drained net of a fall
    CHECK(TrailingInflow(100, 150, 200) == 150); // claims exceed the fall
    CHECK(TrailingInflow(~uint64_t(0), 0, 0) == ~uint64_t(0));

    // Budget: 10% slice + the fixed seed release, capped at the
    // balance. Seed release = seed/1000 (1 LKYL at the frozen seed).
    CHECK(SeedRelease(PRIZE_SEED) == 100000000ULL);
    CHECK(SeedRelease(0) == 0);
    CHECK(Budget(0, PRIZE_SEED, PRIZE_SLICE_BPS, 0) == 0);                   // no seed, no inflow
    CHECK(Budget(0, PRIZE_SEED, PRIZE_SLICE_BPS, PRIZE_SEED) == 100000000ULL); // release only
    CHECK(Budget(1000, PRIZE_SEED, PRIZE_SLICE_BPS, PRIZE_SEED) == 100000100ULL);
    CHECK(Budget(999, PRIZE_SEED, PRIZE_SLICE_BPS, PRIZE_SEED) == 100000099ULL);
    CHECK(Budget(100, 5, PRIZE_SLICE_BPS, PRIZE_SEED) == 5);   // capped at balance
    // Draw 51 live vector (v1 shape, seed 0): inflow 2,952,381 -> floor 10%.
    CHECK(Budget(2952381, 2952381, PRIZE_SLICE_BPS, 0) == 295238);

    // Winner: the v1 selection math, byte-identical.
    uint8_t seed1[32]; memset(seed1, 7, 32);
    uint8_t seed2[32]; memset(seed2, 9, 32);
    std::vector<std::pair<std::string, uint64_t>> e;
    CHECK(Winner(e, seed1) == "");                        // no entrants
    e.push_back(std::make_pair(std::string("x"), 0));
    CHECK(Winner(e, seed1) == "");                       // zero total
    e.clear();
    e.push_back(std::make_pair(std::string("solo"), 1000));
    CHECK(Winner(e, seed2) == "solo");                   // single entrant
    e.clear();
    e.push_back(std::make_pair(std::string("alice"), 1000));
    e.push_back(std::make_pair(std::string("bob"), 2000));
    // Deterministic: same seed, same winner.
    std::string w1 = Winner(e, seed1);
    CHECK(w1 == Winner(e, seed1));
    // Proportionality over many seeds: bob (2x) wins ~2/3 (Rust mirror
    // runs the same 3000-seed sweep with the same seeds).
    int alice = 0, bob = 0;
    for (uint32_t i = 0; i < 3000; i++)
    {
        uint8_t s[32]; memset(s, 0, 32);
        memcpy(s, &i, 4);
        uint32_t k = 0x9e3779b9u;
        memcpy(s + 4, &k, 4);
        std::string w = Winner(e, s);
        if (w == "alice") alice++;
        else if (w == "bob") bob++;
    }
    double frac = (double)bob / (double)(alice + bob);
    CHECK(frac > 2.0 / 3.0 - 0.03 && frac < 2.0 / 3.0 + 0.03);

    if (failures) { printf("PRIZE KAT GATE FAILED (%d failures)\n", failures); return 1; }
    printf("PRIZE KAT GATE PASSED (0 failures)\n");
    return 0;
}
