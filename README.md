# Lucky Lode Node

The Lucky Lode consensus node — a fork of [VerusCoin](https://github.com/VerusCoin/VerusCoin)
(v1.2.18) carrying the LuckyHash proof-of-work (Argon2id construction,
frozen vectors — doc 05), pre-committable draws, the Lucky Pot, hybrid
PoS, and Lucky Lode's chain parameters and naming.

The Rust reference implementation — miner, pool, wallet core, explorer,
tooling — and the design documents live in the main repository:
[kdsmith18542/LuckyLode](https://github.com/kdsmith18542/LuckyLode).

## Build (Linux)

```sh
./zcutil/build.sh -j"$(nproc)"
./src/luckyd --version
```

The five consensus KAT gates run standalone without a build:

```sh
sh src/crypto/lucky_kat.sh
```

## License

Upstream MIT — `COPYING` is retained verbatim, and upstream copyright
notices remain in source headers (see `NOTICE`). Changes made for
Lucky Lode are licensed GNU GPL-3.0-only, matching the main repository.
