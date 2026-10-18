// KAT gate for the Lucky Pot money rules : frozen vectors
// from the Rust reference (`lm-rewards::pot` tests). Build & run
// standalone:
//   g++ -O2 -std=c++11 -I<repo>/src <repo>/src/crypto/lucky_pot_kat.cpp -o /tmp/pot && /tmp/pot
// Any mismatch exits non-zero.
#include "consensus/lucky_pot.h"

#include <stdio.h>

static int failures = 0;

#define CHECK(cond) do { if (!(cond)) { failures++; printf("FAIL line %d: %s\n", __LINE__, #cond); } else { printf("ok   line %d\n", __LINE__); } } while (0)

using namespace lucky_pot;

static PotState st(uint64_t pot, uint64_t drought) { PotState s; s.pot = pot; s.drought = drought; return s; }
static BlockDraws dr(bool jackpot, bool event, uint64_t tier) { BlockDraws d; d.jackpot = jackpot; d.pot_event = event; d.tier = tier; d.isPow = true; return d; }
static BlockDraws pos(void) { BlockDraws d; d.jackpot = false; d.pot_event = false; d.tier = 0; d.isPow = false; return d; }

int main()
{
    // Levy split is exact fifths at every levy scale.
    {
        const uint64_t levies[] = {0, 1, 4, 5, 7, 100, 4000000};
        for (size_t i = 0; i < sizeof(levies) / sizeof(levies[0]); i++)
        {
            uint64_t levy = levies[i];
            PotPayout p = ApplyPotBlock(0, st(0, 0), levy * 20, 0, dr(false, false, 0));
            if (p.to_pot + p.to_burn != levy / 5 || p.to_reserve + p.to_league != levy - levy / 5)
            {
                failures++;
                printf("FAIL split levy=%llu\n", (unsigned long long)levy);
            }
        }
        printf("ok   levy split fifths\n");
    }

    // Tiers: 10% / 25% / 50%, top tier for out-of-range rolls.
    {
        uint64_t pot = 1000000;
        const struct { uint64_t tier; uint64_t splash; } cases[] = {
            {0, 100000}, {1, 100000}, {69, 100000},
            {70, 250000}, {94, 250000},
            {95, 500000}, {99, 500000}, {100, 500000}, {999, 500000},
        };
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        {
            PotPayout p = ApplyPotBlock(0, st(pot, 0), 0, 0, dr(false, true, cases[i].tier));
            CHECK(p.pot_splash == cases[i].splash);
            CHECK(p.pot == pot - cases[i].splash);
        }
        PotPayout q = ApplyPotBlock(0, st(pot, 0), 0, 0, dr(false, false, 99));
        CHECK(q.pot_splash == 0 && q.pot == pot);
    }

    // Cap overflow burns instead of hoarding.
    {
        uint64_t cap = PotCap(100); // 20000
        PotPayout p = ApplyPotBlock(0, st(cap - 3, 0), 100, 0, dr(false, false, 0));
        CHECK(p.to_pot == 1 && p.to_burn == 0 && p.pot == cap - 3 + 1);
        PotPayout q = ApplyPotBlock(0, st(cap, 0), 100, 20, dr(false, false, 0));
        CHECK(q.to_pot == 0 && q.to_burn == 1 && q.pot == cap);
    }

    // Pity timer: one under the limit advances; at the limit a forced
    // tier-A splash resets the run; a digest event never forces.
    {
        uint64_t base = 80000000ULL, pot = 1000000;
        PotPayout p = ApplyPotBlock(0, st(pot, POT_DROUGHT_LIMIT - 1), base, 0, dr(false, false, 99));
        CHECK(!p.pot_event && !p.pity);
        CHECK(p.drought == POT_DROUGHT_LIMIT);
        CHECK(p.pot_splash == 0);
        PotPayout p2 = ApplyPotBlock(0, st(p.pot, p.drought), base, 0, dr(false, false, 99));
        CHECK(p2.pot_event && p2.pity);
        CHECK(p2.drought == 0);
        CHECK(p2.pot_splash == (p.pot + 800000) / 10);
        PotPayout p3 = ApplyPotBlock(0, st(pot, POT_DROUGHT_LIMIT), base, 0, dr(false, true, 95));
        CHECK(p3.pot_event && !p3.pity);
        CHECK(p3.drought == 0);
        CHECK(p3.pot_splash == (pot + 800000) / 2);
        // PoS finders never collect — the forced splash included. The
        // drought keeps counting; the next PoW block collects.
        PotPayout s1 = ApplyPotBlock(0, st(pot, POT_DROUGHT_LIMIT), base, 0, pos());
        CHECK(!s1.pot_event && !s1.pity && s1.pot_splash == 0);
        CHECK(s1.drought == POT_DROUGHT_LIMIT + 1);
        CHECK(s1.pot == pot + s1.to_pot); // levy credited, nothing taken
        PotPayout s2 = ApplyPotBlock(0, st(pot, s1.drought), base, 0, dr(false, false, 99));
        CHECK(s2.pot_event && s2.pity && s2.pot_splash > 0);
    }

    // The live J1 jackpot (block 21) replayed under the 4/1 split.
    {
        PotPayout p = ApplyPotBlock(39999990ULL, st(0, 0), 80000000ULL, 0, dr(true, false, 0));
        CHECK(p.to_reserve == 3200000ULL);
        CHECK(p.to_pot == 800000ULL);
        CHECK(p.jackpot_bonus == 43199990ULL);
        CHECK(p.reserve == 0);
        CHECK(p.pot == 800000ULL);
        CHECK(p.miner == 76000000ULL + 43199990ULL);
    }

    // Seeded start pays from day one (genesis game-fund seed).
    {
        uint64_t seed = 4200000000ULL;
        PotPayout p = ApplyPotBlock(0, st(seed, 0), 80000000ULL, 0, dr(false, true, 99));
        uint64_t credited = seed + 800000ULL;
        CHECK(p.to_pot == 800000ULL);
        CHECK(p.pot_splash == credited / 2);
        CHECK(p.pot == credited - credited / 2);
    }

    // Conservation sweep: miner + dReserve + dPot + league + burn == R + F.
    {
        struct Case { uint64_t reserve, pot, drought, base, fees; };
        Case cases[] = {
            {0, 0, 0, 100, 2},
            {7, 13, 0, 100, 2},
            {5000, 20000, POT_DROUGHT_LIMIT, 100, 2},
            {0, 0, 0, 0, 1000},
            {39999990ULL, 0, 0, 80000000ULL, 0},
            {1000000, 4200000000ULL, 4000, 12500000000ULL, 500000},
        };
        const bool jackpots[] = {false, true};
        const struct { bool event; uint64_t tier; } draws[] = {
            {false, 0}, {true, 0}, {true, 69}, {true, 70}, {true, 95},
        };
        for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++)
        {
            for (size_t j = 0; j < 2; j++)
            {
                for (size_t e = 0; e < sizeof(draws) / sizeof(draws[0]); e++)
                {
                    PotPayout p = ApplyPotBlock(cases[k].reserve, st(cases[k].pot, cases[k].drought),
                                                cases[k].base, cases[k].fees,
                                                dr(jackpots[j], draws[e].event, draws[e].tier));
                    __uint128_t inflow = (__uint128_t)cases[k].base + cases[k].fees;
                    __uint128_t outflow = (__uint128_t)p.miner + p.reserve + p.pot + p.to_league + p.to_burn
                                          - cases[k].reserve - cases[k].pot;
                    if (outflow != inflow)
                    {
                        failures++;
                        printf("FAIL conservation case %zu j=%d e=%zu t=%llu\n", k, (int)j, e,
                               (unsigned long long)draws[e].tier);
                    }
                }
            }
        }
        printf("ok   conservation sweep\n");
    }

    // Drought run (no digest events, zero levy): pity fires on exactly
    // every (limit+1)-th block and each splash is a tenth of the pot.
    {
        PotState state = st(1000000, 0);
        uint64_t splashes = 0;
        for (uint64_t h = 1; h <= 43210; h++)
        {
            PotPayout p = ApplyPotBlock(0, state, 0, 0, dr(false, false, 0));
            if (p.drought > POT_DROUGHT_LIMIT)
            {
                failures++;
                printf("FAIL drought exceeded at h=%llu\n", (unsigned long long)h);
            }
            if (p.pity)
            {
                splashes++;
                if (p.pot_splash != state.pot / 10 || p.drought != 0)
                {
                    failures++;
                    printf("FAIL pity at h=%llu\n", (unsigned long long)h);
                }
            }
            state = st(p.pot, p.drought);
        }
        if (splashes != 10)
        {
            failures++;
            printf("FAIL pity count %llu\n", (unsigned long long)splashes);
        }
        printf("ok   drought run (10 pities in 43210 blocks)\n");
    }

    printf("\n%s (%d failures)\n", failures ? "POT KAT GATE FAILED" : "POT KAT GATE PASSED", failures);
    return failures ? 1 : 0;
}
