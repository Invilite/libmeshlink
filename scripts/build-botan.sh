#!/usr/bin/env bash
# Builds a small static Botan from third_party/botan with only the algorithms libmeshlink uses.
# Output: third_party/botan/libbotan-3.a and third_party/botan/build/include/public
set -euo pipefail
cd "$(dirname "$0")/../third_party/botan"
./configure.py --disable-shared --build-targets=static --cc=gcc --disable-deprecated-features \
    --minimized-build --without-documentation \
    --enable-modules=aead,chacha20poly1305,chacha,chacha_avx2,poly1305,hmac,sha3,sha2_32,sha2_64,blake2,blake2mac,hkdf,\
ed25519,x25519,x448,pubkey,pem,hex,base64,auto_rng,hmac_drbg,system_rng,processor_rng
make -j"$(nproc)" libs
