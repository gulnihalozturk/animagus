"""Generate non-normative Animagus-AES-v2 primitive fixtures.

Three fixture groups isolate the three keyed-hash uses of the profile:

- ``kdf_cases``: the five SP 800-108r1 working keys, computed with the Python
  standard library HMAC-SHA3-256 and therefore independent of every other
  hash implementation in this repository.
- ``core_cases``: HMAC-SHA3-256 over ``tail || 10 || T`` and
  ``tail || 01 || T``. These inputs are not byte aligned, so the standard
  library cannot compute them; they use ``python/sha3_bits.py``, which is
  itself validated against the NIST bit-oriented SHA3-256 vectors.
- ``tweak_cases``: the full 32-byte HMAC-SHA3-256 output over the MakeTweak
  input ``d || BE64(|N|) || N || AD || 00 || 0^128``, also via sha3_bits.
"""

import argparse
import hashlib
import hmac
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from python.sha3_bits import hmac_sha3_256_bits  # noqa: E402

OUTPUT = ROOT / "test_vectors/ours/HMAC_SHA3_256_ANIMAGUS_V2.json"
DEFAULT_C_HEADER = (
    ROOT / "test_vectors/converted/cstruct/hmac_sha3_animagus_v2_testvecs.h"
)
PROFILE = "Animagus-AES-v2 keyed-hash framing"
PROFILE_VERSION = 2
PROVENANCE = (
    "Repository-generated non-normative primitive fixtures; KDF cases use the "
    "Python standard library HMAC-SHA3-256, framed cases use the NIST "
    "bit-vector-validated python/sha3_bits.py oracle"
)
ROLES = ("head1", "head2", "seed", "ctr", "hash")
ROLE_PLAINTEXT_TAIL = (b"\x01", 2)
ROLE_CIPHERTEXT_TAIL = (b"\x02", 2)
ROLE_TWEAK = (b"\x00", 2)
ZERO_BLOCK = (bytes(16), 128)


def _kdf(master_key: bytes, role: str) -> bytes:
    fixed_input = (
        (1).to_bytes(4, "big")
        + b"animagus/" + role.encode("ascii")
        + b"\x00"
        + (8 * len(master_key)).to_bytes(4, "big")
    )
    return hmac.new(master_key, fixed_input, hashlib.sha3_256).digest()[
        :len(master_key)
    ]


def _core_digest(key: bytes, tail: bytes, role: tuple[bytes, int],
                 tweak: bytes) -> bytes:
    return hmac_sha3_256_bits(key, [(tail, 8 * len(tail)), role, (tweak, 128)])


def _tweak_digest(key: bytes, application: int, nonce: bytes,
                  ad: bytes) -> bytes:
    framed = (
        bytes((application,)) + (8 * len(nonce)).to_bytes(8, "big") + nonce + ad
    )
    return hmac_sha3_256_bits(
        key, [(framed, 8 * len(framed)), ROLE_TWEAK, ZERO_BLOCK]
    )


def _vectors() -> dict[str, object]:
    kdf_cases = []
    core_cases = []
    tweak_cases = []
    for key_length in (16, 24, 32):
        key = bytes(range(key_length))
        kdf_cases.append(
            {
                "master_key": key.hex(),
                **{role: _kdf(key, role).hex() for role in ROLES},
            }
        )
        for tail in (b"", b"\x00", bytes(range(33))):
            for tweak in (bytes(16), bytes(range(16))):
                core_cases.append(
                    {
                        "ciphertext_digest": _core_digest(
                            key, tail, ROLE_CIPHERTEXT_TAIL, tweak
                        ).hex(),
                        "key": key.hex(),
                        "plaintext_digest": _core_digest(
                            key, tail, ROLE_PLAINTEXT_TAIL, tweak
                        ).hex(),
                        "tail": tail.hex(),
                        "tweak": tweak.hex(),
                    }
                )
        for application, nonce, ad in (
            (1, b"\x00", b""),
            (1, bytes(range(12)), b""),
            (1, bytes(range(12)), bytes(range(64, 77))),
            (2, b"", b""),
            (2, b"", bytes(range(64, 111))),
            (3, b"", b""),
        ):
            tweak_cases.append(
                {
                    "ad": ad.hex(),
                    "application": application,
                    "digest": _tweak_digest(key, application, nonce, ad).hex(),
                    "key": key.hex(),
                    "nonce": nonce.hex(),
                }
            )
    return {
        "algorithm": "HMAC-SHA3-256 Animagus-AES-v2 key derivation and framing",
        "core_cases": core_cases,
        "kdf_cases": kdf_cases,
        "normative": False,
        "profile": PROFILE,
        "profile_version": PROFILE_VERSION,
        "provenance": PROVENANCE,
        "tweak_cases": tweak_cases,
    }


def _encoded_vectors(vectors: dict[str, object]) -> bytes:
    return (json.dumps(vectors, indent=2, sort_keys=True) + "\n").encode("ascii")


def _format_bytes(data: bytes, indent: str = "    ") -> str:
    rows = []
    for offset in range(0, len(data), 12):
        chunk = data[offset:offset + 12]
        rows.append(indent + ", ".join(f"0x{value:02x}" for value in chunk) + ",")
    return "\n".join(rows)


def _emit_buffer(lines: list[str], symbol: str, data: bytes) -> str:
    if not data:
        return "{ 0U, NULL }"
    lines.extend([
        f"static const uint8_t {symbol}[] = {{",
        _format_bytes(data),
        "};",
        "",
    ])
    return f"{{ sizeof({symbol}), {symbol} }}"


def _encoded_c_header(vectors: dict[str, object]) -> bytes:
    lines = [
        "/*",
        " * Generated by python/generate_primitive_vectors.py.",
        f" * profile: {vectors['profile']}",
        f" * profile version: {vectors['profile_version']}",
        " * normative: no",
        f" * provenance: {vectors['provenance']}",
        " */",
        "#pragma once",
        "",
        '#include "testvec.h"',
        "",
        "struct hmac_sha3_animagus_v2_kdf_testvec {",
        "    struct testvec_buffer master_key;",
        "    struct testvec_buffer head1;",
        "    struct testvec_buffer head2;",
        "    struct testvec_buffer seed;",
        "    struct testvec_buffer ctr;",
        "    struct testvec_buffer hash;",
        "};",
        "",
        "struct hmac_sha3_animagus_v2_core_testvec {",
        "    struct testvec_buffer key;",
        "    struct testvec_buffer tail;",
        "    struct testvec_buffer tweak;",
        "    struct testvec_buffer plaintext_digest;",
        "    struct testvec_buffer ciphertext_digest;",
        "};",
        "",
        "struct hmac_sha3_animagus_v2_tweak_testvec {",
        "    unsigned int application;",
        "    struct testvec_buffer key;",
        "    struct testvec_buffer nonce;",
        "    struct testvec_buffer ad;",
        "    struct testvec_buffer digest;",
        "};",
        "",
    ]

    kdf_entries = []
    for index, case in enumerate(vectors["kdf_cases"]):
        fields = []
        for name in ("master_key",) + ROLES:
            symbol = f"hmac_sha3_animagus_v2_kdf_{index}_{name}"
            fields.append(_emit_buffer(lines, symbol, bytes.fromhex(case[name])))
        kdf_entries.append(
            "    {\n" + "".join(f"        {field},\n" for field in fields) + "    },"
        )

    core_entries = []
    for index, case in enumerate(vectors["core_cases"]):
        fields = []
        for name in ("key", "tail", "tweak", "plaintext_digest",
                     "ciphertext_digest"):
            symbol = f"hmac_sha3_animagus_v2_core_{index}_{name}"
            fields.append(_emit_buffer(lines, symbol, bytes.fromhex(case[name])))
        core_entries.append(
            "    {\n" + "".join(f"        {field},\n" for field in fields) + "    },"
        )

    tweak_entries = []
    for index, case in enumerate(vectors["tweak_cases"]):
        fields = [f"{case['application']}U"]
        for name in ("key", "nonce", "ad", "digest"):
            symbol = f"hmac_sha3_animagus_v2_tweak_{index}_{name}"
            fields.append(_emit_buffer(lines, symbol, bytes.fromhex(case[name])))
        tweak_entries.append(
            "    {\n" + "".join(f"        {field},\n" for field in fields) + "    },"
        )

    lines.append(
        "static const struct hmac_sha3_animagus_v2_kdf_testvec "
        "hmac_sha3_animagus_v2_kdf_testvecs[] = {"
    )
    lines.extend(kdf_entries)
    lines.extend(["};", ""])
    lines.append(
        "static const struct hmac_sha3_animagus_v2_core_testvec "
        "hmac_sha3_animagus_v2_core_testvecs[] = {"
    )
    lines.extend(core_entries)
    lines.extend(["};", ""])
    lines.append(
        "static const struct hmac_sha3_animagus_v2_tweak_testvec "
        "hmac_sha3_animagus_v2_tweak_testvecs[] = {"
    )
    lines.extend(tweak_entries)
    lines.extend(["};", ""])
    return "\n".join(lines).encode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--c-header", type=pathlib.Path)
    args = parser.parse_args()
    vectors = _vectors()
    generated = _encoded_vectors(vectors)
    header_path = args.c_header
    if args.check and header_path is None:
        header_path = DEFAULT_C_HEADER
    generated_header = _encoded_c_header(vectors)
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_bytes() != generated:
            print(f"{OUTPUT} is out of date", file=sys.stderr)
            return 1
        if (header_path is not None and
                (not header_path.is_file() or
                 header_path.read_bytes() != generated_header)):
            print(f"{header_path} is out of date", file=sys.stderr)
            return 1
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_bytes(generated)
    if header_path is not None:
        header_path.parent.mkdir(parents=True, exist_ok=True)
        header_path.write_bytes(generated_header)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
