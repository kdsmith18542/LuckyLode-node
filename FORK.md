# Fork notes — Lucky Lode EmberHash branch

Fork of [VerusCoin/VerusCoin](https://github.com/VerusCoin/VerusCoin) for the
EmberHash PoW swap. The swap's executable specs live in the main repo
(`lm-pow` for the hash + difficulty, `lm-rewards` for the jackpot path);
internal decision/work-plan docs are deliberately not published.

- Upstream: `master` @ `5ec1d83` (v1.2.18), fetched 2026-10-11
- **Our work lives on branch `emberhash-swap`** (upstream `master` stays
  pristine; diff the fork delta with `git diff master..emberhash-swap`)
- License: MIT (see `COPYING`); vendored deps carry their own licenses
  (`src/crypto/blake3/LICENSE_CC0`, `src/crypto/argon2/LICENSE`);
  rebrand attribution applies before any release.

What's on `emberhash-swap`:

- `src/crypto/blake3/` — vendored BLAKE3 (C, CC0)
- `src/crypto/argon2/` — vendored Argon2 reference (CC0/Apache-2.0)
- `src/crypto/ember_hash.{h,cpp}` — EmberHash v1 port (main repo doc 05 rev 1.0)
- `src/crypto/ember_difficulty.{h,cpp}` — exact integer LWMA retarget
  (doc 05 §5.3) using the node's real `arith_uint256`
- `src/crypto/ember_kat.cpp`, `src/crypto/ember_diff_kat.cpp` — KAT gates
- `src/crypto/ember_kat.sh` — builds + runs both gates standalone

```sh
# needs libsodium headers for verus's arith_uint256.cpp:
src/crypto/ember_kat.sh                     # or SODIUM_INC=... prefix
```

Both gates PASS byte-for-byte against the Rust reference (`lm-pow`):
hash vectors §5.4 + Addendum A1; difficulty V1–V4 + POW_LIMIT roundtrip.
Next: D1 signature change + init/pow/miner wiring — the first step needing
the full node build environment.
