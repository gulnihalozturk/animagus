# Animagus

This repository implements the AES and HMAC-SHA3-256 instantiation of
[*ANIMAGUS: A Provably Secure Tweakable Wide-Block Mode*](https://eprint.iacr.org/2026/229)
(IACR ePrint 2026/229, revision 2026-10-23). It is a length-preserving
tweakable cipher for messages from 32 through `2^52` bytes with a fixed
16-byte tweak, plus the paper's three derived interfaces.

The implementation follows the paper byte for byte: five SP 800-108 working
keys derived from one master key, two independently keyed head branches
coupled through an encrypted seed, literal two-bit role codes in the keyed-hash
inputs, and the paper's `MakeTweak` derived function. It restricts the paper's
bit-granular inputs to whole bytes (messages, nonces, associated data, and
contexts), and it reads the paper's literal bit strings under the FIPS 202
bit-string convention, which the paper does not name. On byte-aligned inputs
it agrees with any bit-granular implementation that makes the same reading.
The normative byte-level description is
[`docs/animagus-v2-profile.md`](docs/animagus-v2-profile.md).

The repository implements the core permutation, tweak derivation, and the
paper's three derived interfaces in
[`include/animagus_derived.h`](include/animagus_derived.h): nonce-based AEAD,
tweakable encryption with a variable-length context, and deterministic
authenticated encryption. The core by itself does not authenticate ciphertext
or tweak. Only the AEAD and DAE interfaces verify the paper's fixed
authentication block. The paper's theorem covers the core; the paper states
that all three derived interfaces need analysis beyond it.

This is research software. It has not received an independent security audit
and is not represented as suitable for production use.

## Building

You need a C11 compiler, [Meson](https://mesonbuild.com/), and
[Ninja](https://ninja-build.org/). The C library has no runtime dependencies.
Linux x86_64 is the primary tested host. Linux and Android AArch64 build, but a
real AArch64 runtime test is still required before claiming runtime validation
for that target.

```sh
meson setup build/release --buildtype=release
meson compile -C build/release
meson test -C build/release --print-errorlogs
```

Every build type compiles with `-Wall -Wextra -Wpedantic -Werror`;
`--buildtype=debug` additionally disables optimization and adds debug
information. Use `meson setup --reconfigure` to update an existing compatible
tree or `--wipe` when its configuration cannot be reused.

On x86_64 and AArch64, the accelerated AES assembly is built alongside the
portable scalar backend. `ANIMAGUS_BACKEND_AUTO` selects hardware AES only when
the CPU supports it; `ANIMAGUS_BACKEND_PORTABLE` forces scalar AES; forcing
`ANIMAGUS_BACKEND_HARDWARE` on an unsupported host returns
`ANIMAGUS_ERR_BACKEND`.

## C API

The public interfaces are [`include/animagus.h`](include/animagus.h) (core)
and [`include/animagus_derived.h`](include/animagus_derived.h) (the paper's
Section 2.2 interfaces). The core header defines `ANIMAGUS_PROFILE_NAME` and
`ANIMAGUS_PROFILE_VERSION` in addition to the key, length, state, and
buffer-overlap contract.

```c
animagus_ctx ctx;
int status = animagus_init(&ctx, key, key_len);

if (status != ANIMAGUS_OK) {
    return status;
}
/* Nonce-based AEAD: ciphertext is message_len + ANIMAGUS_AUTH_SIZE bytes. */
status = animagus_aead_encrypt(&ctx, ciphertext, message, message_len,
                               nonce, nonce_len, ad, ad_len);
/* ... */
status = animagus_aead_decrypt(&ctx, message, ciphertext, ciphertext_len,
                               nonce, nonce_len, ad, ad_len);
/* ANIMAGUS_ERR_AUTH: the authentication block did not verify and the
 * message buffer has been zeroed. */
animagus_clear(&ctx);
```

`animagus_dae_encrypt()`/`animagus_dae_decrypt()` take only the message, and
`animagus_tweakable_encrypt()`/`animagus_tweakable_decrypt()` take a context
instead of a nonce and perform no authentication. For AEAD and DAE the message
may be placed at offset 16 of the ciphertext buffer for in-place operation;
the tweakable interface and the core operate in place with `dst == src`.

The core takes a 16-byte tweak directly:

```c
uint8_t tweak[ANIMAGUS_TWEAK_SIZE];
status = animagus_derive_tweak(&ctx, tweak, context, context_len);
if (status == ANIMAGUS_OK) {
    status = animagus_encrypt(&ctx, ciphertext, plaintext, message_len,
                              tweak);
}
```

`animagus_derive_tweak()` is the paper's `MakeTweak(2, empty, V)`, the only
derived tweak the paper defines for direct use with the core. The AEAD and DAE
tweaks are derived inside the library and cannot be obtained through the API,
so a core decryption cannot be aimed at an authenticated ciphertext's tweak.
Under one key the remaining exposure is a `2^-128` collision between
truncated derived tweaks; separate keys per interface remove it. Do not offer
core decryption with attacker-controlled tweaks under a key that also protects
AEAD or DAE ciphertexts.

`dst == src` operates in place. Otherwise source and destination must be
disjoint, and the destination must not overlap the tweak. Validation errors
are returned before the destination is modified.

Concurrent encrypt/decrypt calls using one unchanged initialized context are
supported. Initialization, reinitialization, and clearing require caller
synchronization. Failed initialization leaves a previously initialized context
unchanged; callers must not assume a failed re-key erased the old key.

## Concrete profile

- A 16-, 24-, or 32-byte master key is expanded with the SP 800-108 Rev. 1
  counter-mode KDF over HMAC-SHA3-256 into five same-length working keys with
  labels `animagus/head1`, `animagus/head2`, `animagus/seed`, `animagus/ctr`,
  and `animagus/hash`.
- The two core hash inputs are `tail || 10 || T` and `tail || 01 || T`, where
  `10` and `01` are literal two-bit strings and `T` is the 16-byte tweak.
- Bit strings follow the FIPS 202 convention for SHA-3 inputs (bit `i` of a
  string is bit `i mod 8` of byte `i div 8`, least significant bit first), so
  the role codes `10`, `01`, and `00` occupy the two low bits of the bytes
  `0x01`, `0x02`, and `0x00`. Integer fields are ordinary big-endian byte
  strings.
- `F = E_head1(P1 xor A2)`, `B = E_head2(P2 xor A1)`, `J = E_seed(F xor B)`,
  `F* = F xor J`, `B* = B xor J`, `C1 = E_head1(F*) xor A4`,
  `C2 = E_head2(B*) xor A3`.
- Tail block `i` uses `AES_K_ctr(J xor BE128(i))`, starting at zero. A partial
  final block uses the leading AES-output bytes; an empty tail generates no
  counter block.
- Tweak derivation hashes `d || BE64(bit length of N) || N || AD || 00 ||
  0^128` under the hash key and keeps the first 16 bytes; `d` is 1 for AEAD,
  2 for tweakable encryption, and 3 for DAE.
- AEAD and DAE prepend the fixed block `0^128` to the message and verify it in
  constant time on decryption.

Ciphertexts of the retired `Animagus-AES-v1` repository profile are not
compatible with this profile. Bind `ANIMAGUS_PROFILE_NAME` and
`ANIMAGUS_PROFILE_VERSION` to stored ciphertext.

## Side-channel posture

The AES-NI and ARMv8 Crypto Extensions backends use hardware instructions and
are constant-time by construction with respect to table lookups. The portable
Linux-derived AES backend uses a volatile S-box and full-table prefetch as a
best-effort cache-timing mitigation; it is not a strict constant-time
implementation, and its unmodified source leaves round-state locals on the
stack unwiped. The SHA3/HMAC code has no secret-indexed lookup and no
data-dependent branch: the bit-granular absorption used after the role codes
is branch-free, and the Keccak temporaries are wiped after every permutation.
The authentication-block comparison is a data-independent scan.

Deployments with a strict side-channel requirement should require a supported
hardware backend and independently assess the complete compiler, platform, and
calling environment.

## Test vectors

The three construction files under `test_vectors/ours/Animagus/` are normative
Animagus-AES-v2 vectors, including MakeTweak, AEAD, DAE, and
tweakable-interface cases. They are produced by the Python oracle in
`python/animagus.py`, which uses PyCryptodomex for AES and the standard library
HMAC for the key derivation; the non-byte-aligned core hashes use the
repository's own bit-level SHA3 (`python/sha3_bits.py`), which is structurally
parallel to the C code and is checked against all 1089 NIST CAVP bit-oriented
SHA3-256 short-message vectors in `test_vectors/external/nist/`. The
keyed-hash primitive fixture is repository-generated and explicitly
non-normative.

```sh
python3 -m pip install pycryptodomex
python3 python/generate_primitive_vectors.py \
  --c-header test_vectors/converted/cstruct/hmac_sha3_animagus_v2_testvecs.h
python3 python/generate_test_vectors.py
python3 python/generate_primitive_vectors.py --check
python3 python/generate_test_vectors.py --check
python3 -m unittest discover -s python -p 'test_*.py' -v
```

Do not hand-edit generated JSON or C fixtures. Both `--check` commands must pass
before publication.

## Benchmarking

```sh
./build/release/benchmark/animagus-cipherbench \
  --bufsize=4096 --ntries=25 --key-size=256 --backend=auto
```

Only benchmark a release build; a debug build materially understates
throughput. [`benchmark/README.md`](benchmark/README.md) documents the uniform
comparison workflow, provenance, and interpretation limits.

## Licensing

`third_party/` contains Linux-kernel-derived AES sources covered by GPLv2-family
licenses rather than the root MIT license. The scalar source is compiled into
every build, so a linked `libanimagus` or executable is not a purely MIT
artifact. Distributors must satisfy the applicable GPL terms and preserve the
MIT notices. [`third_party/README.md`](third_party/README.md) records the exact
snapshot, per-file hashes, licenses, and boundary.
