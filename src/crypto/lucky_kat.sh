#!/bin/sh
# Standalone build+run of the LuckyHash KAT gate (no autotools needed).
# Usage: verus/src/crypto/lucky_kat.sh   (from anywhere)
set -e
DIR=$(dirname "$0")
OUT=$(mktemp -d)
CC=${CC:-gcc}
CXX=${CXX:-g++}
# libsodium headers are needed only to compile verus's arith_uint256.cpp
# (crypto/common.h includes sodium.h). Override with SODIUM_INC=... or have
# pkg-config find libsodium.
SODIUM_INC=${SODIUM_INC:-$(pkg-config --cflags-only-I libsodium 2>/dev/null || true)}
if [ -z "$SODIUM_INC" ]; then
    echo "warn: libsodium include not found (set SODIUM_INC); diff KAT will be skipped" >&2
fi
# The tree's compat/endian.h + byteswap.h define fallbacks unless the
# autotools config says the platform provides them. Standalone builds say so.
SYS_DEFS="-DHAVE_ENDIAN_H=1 -DHAVE_BYTESWAP_H=1 \
-DHAVE_DECL_HTOBE16=1 -DHAVE_DECL_HTOLE16=1 -DHAVE_DECL_BE16TOH=1 -DHAVE_DECL_LE16TOH=1 \
-DHAVE_DECL_HTOBE32=1 -DHAVE_DECL_HTOLE32=1 -DHAVE_DECL_BE32TOH=1 -DHAVE_DECL_LE32TOH=1 \
-DHAVE_DECL_HTOBE64=1 -DHAVE_DECL_HTOLE64=1 -DHAVE_DECL_BE64TOH=1 -DHAVE_DECL_LE64TOH=1 \
-DHAVE_DECL_BSWAP_16=1 -DHAVE_DECL_BSWAP_32=1 -DHAVE_DECL_BSWAP_64=1"

# BLAKE3: portable path only for the KAT gate. Autotools wiring (follow-up)
# adds per-file SIMD flags (-msse4.1, -mavx2, -mavx512f -mavx512vl) for
# performance; the portable path is bit-identical. NOTE: BLAKE3_USE_NEON=0
# is the real override (blake3_impl.h autodetects AArch64 and the dispatch
# then references blake3_hash_many_neon, which this script never compiles —
# caught by the aarch64 CI leg); the BLAKE3_NO_* defines are x86-only.
B3FLAGS="-DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_AVX2 -DBLAKE3_NO_AVX512 -DBLAKE3_USE_NEON=0"
for f in "$DIR"/blake3/blake3.c "$DIR"/blake3/blake3_dispatch.c "$DIR"/blake3/blake3_portable.c; do
    $CC -O2 $B3FLAGS -c -I"$DIR/blake3" "$f" -o "$OUT/$(basename "$f" .c).o"
done
# Argon2 reference (portable ref.c path).
for f in "$DIR"/argon2/argon2.c "$DIR"/argon2/core.c "$DIR"/argon2/encoding.c \
         "$DIR"/argon2/ref.c "$DIR"/argon2/thread.c "$DIR"/argon2/blake2/blake2b.c; do
    $CC -O2 -c -I"$DIR/argon2" -I"$DIR/argon2/blake2" "$f" -o "$OUT/$(basename "$f" .c).o"
done

$CXX -O2 -I"$(dirname "$DIR")" \
    "$DIR/lucky_hash.cpp" "$DIR/lucky_kat.cpp" "$OUT"/*.o -o "$OUT/lucky_kat" \
    -lpthread
$CXX -O2 -I"$(dirname "$DIR")" $SODIUM_INC $SYS_DEFS \
    "$DIR/lucky_difficulty.cpp" "$DIR/lucky_diff_kat.cpp" \
    "$(dirname "$DIR")/arith_uint256.cpp" "$(dirname "$DIR")/uint256.cpp" \
    -o "$OUT/lucky_diff_kat"
"$OUT/lucky_kat"
echo
"$OUT/lucky_diff_kat"

# Jackpot money KAT (header-only math, no node libraries needed).
$CXX -O2 -std=c++11 -I"$(dirname "$DIR")" "$DIR/lucky_jackpot_kat.cpp" -o "$OUT/lucky_jackpot_kat"
"$OUT/lucky_jackpot_kat"

# Lucky Pot money KAT (header-only math; includes jackpot.h).
$CXX -O2 -std=c++11 -I"$(dirname "$DIR")" "$DIR/lucky_pot_kat.cpp" -o "$OUT/lucky_pot_kat"
"$OUT/lucky_pot_kat"

# Prize Fund money KAT (doc 06 §6.7, rev 1.3): header-only math.
$CXX -O2 -std=c++11 -I"$(dirname "$DIR")" "$DIR/lucky_prize_kat.cpp" -o "$OUT/lucky_prize_kat"
"$OUT/lucky_prize_kat"

# Pre-committable draw trigger KAT (doc 06 rev 1.2): uint256 + sha256.
$CXX -O2 -I"$(dirname "$DIR")" $SODIUM_INC $SYS_DEFS \
    "$DIR/lucky_draw_kat.cpp" \
    "$(dirname "$DIR")/arith_uint256.cpp" "$(dirname "$DIR")/uint256.cpp" \
    "$DIR/sha256.cpp" \
    -o "$OUT/lucky_draw_kat"
"$OUT/lucky_draw_kat"

# Seed-fund money KAT (internal/20: faucet/dev reserves; header-only math).
$CXX -O2 -std=c++11 -I"$(dirname "$DIR")" "$DIR/lucky_seed_kat.cpp" -o "$OUT/lucky_seed_kat"
"$OUT/lucky_seed_kat"

# Solo-PoS liveness KAT (internal/22: bounded stake attempts in the PoS
# nonce + legacy bit-identity). Needs the portable haraka + clhash (no AES).
$CC -O2 $SYS_DEFS -c -I"$DIR" "$DIR/haraka_portable.c" -o "$OUT/haraka_portable.o"
$CXX -O2 -I"$(dirname "$DIR")" $SODIUM_INC $SYS_DEFS \
    "$DIR/lucky_pos_kat.cpp" \
    "$(dirname "$DIR")/primitives/nonce.cpp" \
    "$(dirname "$DIR")/arith_uint256.cpp" "$(dirname "$DIR")/uint256.cpp" \
    "$DIR/sha256.cpp" \
    "$DIR/verus_hash.cpp" "$DIR/verus_clhash_portable.cpp" \
    "$OUT/haraka_portable.o" \
    -I"$(dirname "$DIR")/univalue/include" \
    -o "$OUT/lucky_pos_kat" -lpthread
"$OUT/lucky_pos_kat"
