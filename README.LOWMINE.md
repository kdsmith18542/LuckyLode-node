# verus/ — fork working tree (upstream + Lowmine branch)

Fork of [VerusCoin/VerusCoin](https://github.com/VerusCoin/VerusCoin) for the
P1 EmberHash swap (decision record: `../08-fork-decision.md`, work plan:
`../10-pow-swap-map.md`).

- Upstream: `master` @ `5ec1d83` (v1.2.18), shallow clone, fetched 2026-10-11
- **Our work lives on branch `lowmine-pow-eval`** (upstream `master` stays
  pristine; diff the fork delta with `git diff master..lowmine-pow-eval`)
- License: MIT (see `COPYING`); vendored deps carry their own licenses
  (`src/crypto/blake3/LICENSE_CC0`, `src/crypto/argon2/LICENSE`);
  rebrand checklist attribution still applies before any release.

Status on `lowmine-pow-eval` (uncommitted work — commit when directed):

- `src/crypto/blake3/` — vendored BLAKE3 (C, CC0)
- `src/crypto/argon2/` — vendored Argon2 reference (CC0/Apache-2.0)
- `src/crypto/ember_hash.{h,cpp}` — EmberHash v1 port (doc 05 rev 1.0)
- `src/crypto/ember_difficulty.{h,cpp}` — exact integer LWMA retarget
  (doc 05 §5.3) using the node's real `arith_uint256`
- `src/crypto/ember_kat.cpp`, `src/crypto/ember_diff_kat.cpp` — KAT gates
- `src/crypto/ember_kat.sh` — builds + runs both gates standalone

```sh
# needs libsodium headers for verus's arith_uint256.cpp:
verus/src/crypto/ember_kat.sh                     # or SODIUM_INC=... prefix
```

Both gates currently PASS byte-for-byte against the Rust reference
(`../lm-pow`): hash vectors §5.4 + Addendum A1; difficulty V1–V4 +
POW_LIMIT roundtrip. Next tasks (10-pow-swap-map §10.6): D1 signature
change + init/pow/miner wiring — first step needing the full node build.
