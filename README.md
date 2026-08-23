# Animagus

This repository implements a security-hardened AES profile derived from the
accordion construction in
[*ANIMAGUS: A Provably Secure Accordion Mode of Operation*](https://eprint.iacr.org/2026/229).
It is a length-preserving tweakable cipher for messages from 32 through
`2^52` bytes, with either an empty or 16-byte tweak.

The implementation uses domain-separated AES, core-HMAC, and tweak-HMAC
subkeys with injective byte framing for all variable-length hash inputs. These
hardening choices differ from the construction described in the paper, so the
paper's proof does not directly establish the security of this implementation.
Independent cryptographic review is required.

The repository implements the accordion permutation and framed tweak
derivation. The higher-level AEAD, DAE, and authentication-value constructions
are out of scope. Animagus by itself does not authenticate ciphertext or tweak,
so successful decryption says nothing about authenticity.

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

`--buildtype=debug` gives the strict `-Werror` development build. Use
`meson setup --reconfigure` to update an existing compatible tree or `--wipe`
when its configuration cannot be reused.

On x86_64 and AArch64, the accelerated AES assembly is built alongside the
portable scalar backend. `ANIMAGUS_BACKEND_AUTO` selects hardware AES only when
the CPU supports it; `ANIMAGUS_BACKEND_PORTABLE` forces scalar AES; forcing
`ANIMAGUS_BACKEND_HARDWARE` on an unsupported host returns
`ANIMAGUS_ERR_BACKEND`.

## C API

The public interface is [`include/animagus.h`](include/animagus.h). The header
defines `ANIMAGUS_PROFILE_NAME` and `ANIMAGUS_PROFILE_VERSION` in addition to
the key, length, state, and buffer-overlap contract.

```c
animagus_ctx ctx;
uint8_t tweak[ANIMAGUS_TWEAK_SIZE];
int status = animagus_init(&ctx, key, key_len);

if (status != ANIMAGUS_OK) {
    return status;
}
status = animagus_derive_tweak(&ctx, tweak, nonce, nonce_len, ad, ad_len);
if (status == ANIMAGUS_OK) {
    status = animagus_encrypt(&ctx, ciphertext, plaintext, message_len,
                              tweak, sizeof(tweak));
}
animagus_clear(&ctx);
```

`dst == src` operates in place. Otherwise source and destination must be
disjoint, and the destination must not overlap a nonempty tweak. Validation
errors are returned before the destination is modified.

Concurrent encrypt/decrypt calls using one unchanged initialized context are
supported. Initialization, reinitialization, and clearing require caller
synchronization. Failed initialization leaves a previously initialized context
unchanged; callers must not assume a failed re-key erased the old key.

## Concrete profile

The implementation uses the following profile:

- A 16-, 24-, or 32-byte master key is expanded with HMAC-SHA3-256 into a
  same-length AES key, a 32-byte core-HMAC key, and a 32-byte tweak-HMAC key.
- The two core HMAC inputs encode a profile label, a one-byte domain, 64-bit
  tail and tweak lengths, the tail, and the tweak.
- Tweak derivation encodes a profile label, 64-bit nonce and associated-data
  lengths, the nonce, and the associated data, then takes the first 16 bytes of
  HMAC-SHA3-256.
- Empty and 16-byte tweaks may safely share a master key and context.
- Tail block `i` uses `AES_K_AES(J XOR BE128(i))`, starting at zero. A partial
  final block uses the leading AES-output bytes; an empty tail generates no
  counter block.

## Side-channel posture

The AES-NI and ARMv8 Crypto Extensions backends use hardware instructions and
are constant-time by construction with respect to table lookups. The portable
Linux-derived AES backend uses a volatile S-box and full-table prefetch as a
best-effort cache-timing mitigation; it is not a strict constant-time
implementation. The scalar SHA3/HMAC code has no secret-indexed lookup or
secret-dependent branch.

Deployments with a strict side-channel requirement should require a supported
hardware backend and independently assess the complete compiler, platform, and
calling environment.

## Test vectors

The three construction files under `test_vectors/ours/Animagus/` are normative
Animagus vectors. They are produced by the independently structured Python
oracle, which uses PyCryptodomex for AES. The framed-HMAC primitive fixture is
repository-generated and explicitly non-normative.

```sh
python3 -m pip install pycryptodomex
python3 python/generate_primitive_vectors.py \
  --c-header test_vectors/converted/cstruct/hmac_sha3_animagus_v1_testvecs.h
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
