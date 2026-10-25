"""Independent oracle for the repository's Animagus-AES-v2 profile.

Animagus-AES-v2 is a byte-for-byte implementation of the AES/HMAC-SHA3-256
instantiation in IACR ePrint 2026/229 (revision 2026-10-23), restricted to
byte-aligned messages. The key derivation uses the Python standard library
HMAC so that it is computed independently of ``python/sha3_bits.py``; the
core hash inputs are not byte aligned, so they use that bit-level oracle.

The module also implements the paper's derived interfaces (Section 2.2):
nonce-based AEAD, tweakable encryption with a variable-length context, and
deterministic authenticated encryption. The authenticated interfaces prepend
the fixed 16-byte authentication block ``AUD = 0^128`` and verify it after
core decryption.
"""

import hashlib
import hmac

from Cryptodome.Cipher import AES

from python.sha3_bits import hmac_sha3_256_bits


BLOCK_BYTES = 16
TWEAK_BYTES = 16
MAX_MESSAGE_BYTES = 1 << 52
MAX_FRAMED_BYTES = (1 << 61) - 1
VALID_KEY_BYTES = (16, 24, 32)
PROFILE_NAME = "Animagus-AES-v2"
PROFILE_VERSION = 2
PAPER_REVISION = "IACR ePrint 2026/229, revision 2026-10-23"

APPLICATION_AEAD = 1
APPLICATION_TWEAKABLE = 2
APPLICATION_DAE = 3
VALID_APPLICATIONS = (APPLICATION_AEAD, APPLICATION_TWEAKABLE, APPLICATION_DAE)

AUTH_BYTES = BLOCK_BYTES
AUTH_BLOCK = bytes(AUTH_BYTES)
MIN_DERIVED_MESSAGE_BYTES = AUTH_BYTES
MAX_DERIVED_MESSAGE_BYTES = MAX_MESSAGE_BYTES - AUTH_BYTES

WORKING_KEY_ROLES = ("head1", "head2", "seed", "ctr", "hash")

# Two-bit role codes in FIPS 202 bit order: bit i of the string is bit
# (i mod 8) of byte (i div 8), least significant bit first. The paper's
# literal strings 10, 01, and 00 therefore become the bytes below.
_ROLE_PLAINTEXT_TAIL = (b"\x01", 2)
_ROLE_CIPHERTEXT_TAIL = (b"\x02", 2)
_ROLE_TWEAK = (b"\x00", 2)
_ZERO_BLOCK = (bytes(BLOCK_BYTES), 8 * BLOCK_BYTES)


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def derive_working_keys(key: bytes) -> dict[str, bytes]:
    """SP 800-108r1 counter-mode KDF with HMAC-SHA3-256, one iteration."""
    if len(key) not in VALID_KEY_BYTES:
        raise ValueError("AES master key must be 16, 24, or 32 bytes")
    key_bits = 8 * len(key)
    keys = {}
    for role in WORKING_KEY_ROLES:
        fixed_input = (
            (1).to_bytes(4, "big")
            + b"animagus/" + role.encode("ascii")
            + b"\x00"
            + key_bits.to_bytes(4, "big")
        )
        keys[role] = hmac.new(key, fixed_input, hashlib.sha3_256).digest()[
            :len(key)
        ]
    return keys


def _core_hash(
    hash_key: bytes, tail: bytes, role: tuple[bytes, int], tweak: bytes
) -> bytes:
    return hmac_sha3_256_bits(
        hash_key,
        [(tail, 8 * len(tail)), role, (tweak, 8 * TWEAK_BYTES)],
    )


def _ctr(
    aes, seed: bytes, length: int
) -> tuple[bytes, list[dict[str, object]]]:
    output = bytearray()
    blocks = []
    for index in range((length + BLOCK_BYTES - 1) // BLOCK_BYTES):
        counter = _xor(seed, index.to_bytes(BLOCK_BYTES, "big"))
        stream = aes.encrypt(counter)
        blocks.append(
            {"index": index, "counter": counter.hex(), "stream": stream.hex()}
        )
        output.extend(stream)
    return bytes(output[:length]), blocks


def _validate_message_length(length: int) -> None:
    if length < 2 * BLOCK_BYTES:
        raise ValueError("Animagus messages must be at least 32 bytes")
    if length > MAX_MESSAGE_BYTES:
        raise ValueError("Animagus messages must be at most 2^52 bytes")


def _validate(key: bytes, tweak: bytes, message: bytes) -> None:
    if len(key) not in VALID_KEY_BYTES:
        raise ValueError("AES master key must be 16, 24, or 32 bytes")
    if len(tweak) != TWEAK_BYTES:
        raise ValueError(
            "Animagus tweaks must be exactly 16 bytes; "
            "derive them with derive_tweak()"
        )
    _validate_message_length(len(message))


def _validate_tweak_inputs(application: int, nonce: bytes, ad: bytes) -> None:
    if application not in VALID_APPLICATIONS:
        raise ValueError("application identifier must be 1, 2, or 3")
    if len(nonce) > MAX_FRAMED_BYTES or len(ad) > MAX_FRAMED_BYTES:
        raise ValueError("nonce and associated data must be below 2^64 bits")
    if application == APPLICATION_AEAD and not nonce:
        raise ValueError("the AEAD interface requires a nonempty nonce")
    if application != APPLICATION_AEAD and nonce:
        raise ValueError("only the AEAD interface carries a nonce")
    if application == APPLICATION_DAE and ad:
        raise ValueError("the DAE interface carries no external context")


def make_tweak(
    key: bytes, application: int, nonce: bytes = b"", ad: bytes = b""
) -> bytes:
    """MakeTweak(d, N, AD) from the paper, under the derived hash key.

    The C library exposes only the tweakable form (d = 2) publicly; the
    AEAD and DAE forms are internal there. The oracle keeps the general
    function so the vectors can cover all three identifiers.
    """
    _validate_tweak_inputs(application, nonce, ad)
    hash_key = derive_working_keys(key)["hash"]
    framed = (
        bytes((application,))
        + (8 * len(nonce)).to_bytes(8, "big")
        + nonce
        + ad
    )
    return hmac_sha3_256_bits(
        hash_key,
        [(framed, 8 * len(framed)), _ROLE_TWEAK, _ZERO_BLOCK],
    )[:TWEAK_BYTES]


def derive_tweak(key: bytes, context: bytes = b"") -> bytes:
    """The public MakeTweak(2, empty, V) form, mirroring the C API."""
    return make_tweak(key, APPLICATION_TWEAKABLE, b"", context)


def _trace(
    keys: dict[str, bytes],
    x1: bytes,
    f: bytes,
    b: bytes,
    j: bytes,
    f_star: bytes,
    b_star: bytes,
    counter_blocks: list[dict[str, object]],
    x2: bytes,
    c1: bytes,
    c2: bytes,
) -> dict[str, object]:
    return {
        "working_keys": {role: keys[role].hex() for role in WORKING_KEY_ROLES},
        "X1": x1.hex(),
        "A1": x1[:BLOCK_BYTES].hex(),
        "A2": x1[BLOCK_BYTES:].hex(),
        "F": f.hex(),
        "B": b.hex(),
        "J": j.hex(),
        "F_star": f_star.hex(),
        "B_star": b_star.hex(),
        "counter_blocks": counter_blocks,
        "X2": x2.hex(),
        "A3": x2[:BLOCK_BYTES].hex(),
        "A4": x2[BLOCK_BYTES:].hex(),
        "C1": c1.hex(),
        "C2": c2.hex(),
    }


def encrypt(
    key: bytes, tweak: bytes, plaintext: bytes, trace: bool = False
) -> bytes | tuple[bytes, dict[str, object]]:
    """Encrypt with the repository's Animagus-AES-v2 profile."""
    _validate(key, tweak, plaintext)
    keys = derive_working_keys(key)
    head1 = AES.new(keys["head1"], AES.MODE_ECB)
    head2 = AES.new(keys["head2"], AES.MODE_ECB)
    seed = AES.new(keys["seed"], AES.MODE_ECB)
    ctr = AES.new(keys["ctr"], AES.MODE_ECB)
    p1, p2, p_tail = plaintext[:16], plaintext[16:32], plaintext[32:]

    x1 = _core_hash(keys["hash"], p_tail, _ROLE_PLAINTEXT_TAIL, tweak)
    a1, a2 = x1[:16], x1[16:]
    f = head1.encrypt(_xor(p1, a2))
    b = head2.encrypt(_xor(p2, a1))
    j = seed.encrypt(_xor(f, b))
    f_star = _xor(f, j)
    b_star = _xor(b, j)
    stream, counter_blocks = _ctr(ctr, j, len(p_tail))
    c_tail = _xor(p_tail, stream)
    x2 = _core_hash(keys["hash"], c_tail, _ROLE_CIPHERTEXT_TAIL, tweak)
    a3, a4 = x2[:16], x2[16:]
    c1 = _xor(head1.encrypt(f_star), a4)
    c2 = _xor(head2.encrypt(b_star), a3)
    ciphertext = c1 + c2 + c_tail

    if not trace:
        return ciphertext
    return ciphertext, _trace(
        keys, x1, f, b, j, f_star, b_star, counter_blocks, x2, c1, c2
    )


def decrypt(
    key: bytes, tweak: bytes, ciphertext: bytes, trace: bool = False
) -> bytes | tuple[bytes, dict[str, object]]:
    """Decrypt with the repository's Animagus-AES-v2 profile.

    The trace uses the encryption-side names from the paper, so it equals
    the trace produced by encrypting the recovered plaintext.
    """
    _validate(key, tweak, ciphertext)
    keys = derive_working_keys(key)
    head1 = AES.new(keys["head1"], AES.MODE_ECB)
    head2 = AES.new(keys["head2"], AES.MODE_ECB)
    seed = AES.new(keys["seed"], AES.MODE_ECB)
    ctr = AES.new(keys["ctr"], AES.MODE_ECB)
    c1, c2, c_tail = ciphertext[:16], ciphertext[16:32], ciphertext[32:]

    x2 = _core_hash(keys["hash"], c_tail, _ROLE_CIPHERTEXT_TAIL, tweak)
    a3, a4 = x2[:16], x2[16:]
    f_star = head1.decrypt(_xor(c1, a4))
    b_star = head2.decrypt(_xor(c2, a3))
    j = seed.encrypt(_xor(f_star, b_star))
    f = _xor(f_star, j)
    b = _xor(b_star, j)
    stream, counter_blocks = _ctr(ctr, j, len(c_tail))
    p_tail = _xor(c_tail, stream)
    x1 = _core_hash(keys["hash"], p_tail, _ROLE_PLAINTEXT_TAIL, tweak)
    a1, a2 = x1[:16], x1[16:]
    p1 = _xor(head1.decrypt(f), a2)
    p2 = _xor(head2.decrypt(b), a1)
    plaintext = p1 + p2 + p_tail

    if not trace:
        return plaintext
    return plaintext, _trace(
        keys, x1, f, b, j, f_star, b_star, counter_blocks, x2, c1, c2
    )


class AuthenticationError(ValueError):
    """Raised when a recovered authentication block is not AUD = 0^128."""


def _validate_derived_message_length(length: int) -> None:
    if length < MIN_DERIVED_MESSAGE_BYTES:
        raise ValueError("authenticated messages must be at least 16 bytes")
    if length > MAX_DERIVED_MESSAGE_BYTES:
        raise ValueError("authenticated messages must be at most 2^52 - 16 bytes")


def _authenticated_encrypt(key: bytes, tweak: bytes, message: bytes) -> bytes:
    _validate_derived_message_length(len(message))
    return encrypt(key, tweak, AUTH_BLOCK + message)


def _authenticated_decrypt(key: bytes, tweak: bytes, ciphertext: bytes) -> bytes:
    _validate_message_length(len(ciphertext))
    recovered = decrypt(key, tweak, ciphertext)
    if not hmac.compare_digest(recovered[:AUTH_BYTES], AUTH_BLOCK):
        raise AuthenticationError("authentication block mismatch")
    return recovered[AUTH_BYTES:]


def aead_encrypt(key: bytes, nonce: bytes, ad: bytes, message: bytes) -> bytes:
    """Nonce-based AEAD: Enc(K, MakeTweak(1, N, AD), 0^128 || M)."""
    # Same precedence as the C library: lengths before the tweak inputs.
    _validate_derived_message_length(len(message))
    tweak = make_tweak(key, APPLICATION_AEAD, nonce, ad)
    return _authenticated_encrypt(key, tweak, message)


def aead_decrypt(key: bytes, nonce: bytes, ad: bytes, ciphertext: bytes) -> bytes:
    """Inverse of aead_encrypt(); raises AuthenticationError on failure."""
    _validate_message_length(len(ciphertext))
    tweak = make_tweak(key, APPLICATION_AEAD, nonce, ad)
    return _authenticated_decrypt(key, tweak, ciphertext)


def tweakable_encrypt(key: bytes, context: bytes, message: bytes) -> bytes:
    """Confidentiality-only interface: Enc(K, MakeTweak(2, empty, V), M)."""
    return encrypt(key, derive_tweak(key, context), message)


def tweakable_decrypt(key: bytes, context: bytes, ciphertext: bytes) -> bytes:
    """Inverse of tweakable_encrypt(); performs no authentication."""
    return decrypt(key, derive_tweak(key, context), ciphertext)


def dae_encrypt(key: bytes, message: bytes) -> bytes:
    """Deterministic AE: Enc(K, MakeTweak(3, empty, empty), 0^128 || M)."""
    _validate_derived_message_length(len(message))
    return _authenticated_encrypt(key, make_tweak(key, APPLICATION_DAE), message)


def dae_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """Inverse of dae_encrypt(); raises AuthenticationError on failure."""
    _validate_message_length(len(ciphertext))
    return _authenticated_decrypt(key, make_tweak(key, APPLICATION_DAE), ciphertext)
