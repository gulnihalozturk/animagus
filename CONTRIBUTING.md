# Contributing

Animagus is research cryptographic software. Keep changes narrow,
reproducible, and explicit about whether they affect the cryptographic profile
or only its implementation.

## Source style and hygiene

- Match the existing C11 style: four-space indentation, existing brace rules,
  `size_t` for byte counts, fixed-width integers for profile encodings, and
  checked public status values.
- Keep C compilation clean under `-Wall -Wextra -Wpedantic -Werror`. Python
  code must remain compatible with Python 3 and follow the existing test style.
- Do not reformat or edit copied files under `third_party/`. If provenance or a
  copied source changes, update `third_party/README.md` and preserve every
  copyright, SPDX, and license notice.
- Run `git diff --check` and ensure build trees, benchmark results, Python
  caches, and PDF intermediates are not staged.

## Profile-sensitive changes

The exact KDF labels, purpose bytes, domain bytes, field widths, byte order,
field order, supported lengths, digest split, and CTR convention are normative.
Changing any of them creates a new cryptographic profile and requires:

1. a version/name decision;
2. an update to the public specification and supporting proof or erratum;
3. new normative vectors and compatibility notes; and
4. independent cryptographic review.

Do not silently replace the domain-separated framing with the literal-paper
framing or same-raw-key behavior.

## Tests and generated vectors

PyCryptodomex is a development-only dependency of the independent AES oracle:

```sh
python3 -m pip install pycryptodomex
```

Regenerate every deterministic fixture with:

```sh
python3 python/generate_primitive_vectors.py \
  --c-header test_vectors/converted/cstruct/hmac_sha3_animagus_v1_testvecs.h
python3 python/generate_test_vectors.py
```

The three Animagus JSON files must remain labeled as normative
`Animagus-AES-v1` vectors with profile version `1`. The framed-HMAC fixture must
remain labeled non-normative. Do not hand-edit generated JSON or C files.

Confirm reproducibility and run the Python suites:

```sh
python3 python/generate_primitive_vectors.py --check
python3 python/generate_test_vectors.py --check
python3 -m unittest discover -s python -p 'test_*.py' -v
```

## Strict and sanitizer builds

Use fresh directories for acceptance builds:

```sh
meson setup build/strict --buildtype=debug \
  -Dc_args='-Wall -Wextra -Wpedantic -Werror'
meson compile -C build/strict
meson test -C build/strict --print-errorlogs

meson setup build/asan --buildtype=debug -Db_sanitize=address
meson compile -C build/asan
meson test -C build/asan --print-errorlogs

meson setup build/ubsan --buildtype=debug -Db_sanitize=undefined
meson compile -C build/ubsan
meson test -C build/ubsan --print-errorlogs
```

Run AddressSanitizer and UndefinedBehaviorSanitizer separately so one failure
cannot mask another. Reconfigure or wipe only an explicitly named build
directory when repeating a local run.

## Benchmark changes

Run `python3 -m pytest benchmark/test_compare_cpb.py` after changing the
comparison harness. The full workflow must reject non-release Meson trees,
record truthful Git provenance, and never label the portable AES backend as
strictly constant-time.
