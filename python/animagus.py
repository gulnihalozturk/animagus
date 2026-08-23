"""Independent oracle for the repository's Animagus-AES-v1 profile."""

from Cryptodome.Cipher import AES

from python.sha3_bits import hmac_sha3_256_bits


BLOCK_BYTES = 16
TWEAK_BYTES = 16
MAX_MESSAGE_BYTES = 1 << 52
VALID_KEY_BYTES = (16, 24, 32)
VALID_TWEAK_BYTES = (0, TWEAK_BYTES)
PROFILE_NAME = "Animagus-AES-v1"
PROFILE_VERSION = 1

_KDF_LABEL = b"Animagus-AES-v1/KDF"
_CORE_LABEL = b"Animagus-AES-v1/CORE"
_TWEAK_LABEL = b"Animagus-AES-v1/TWEAK"
_PLAINTEXT_DOMAIN = 0x01
_CIPHERTEXT_DOMAIN = 0x02


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def _hmac_bytes(key: bytes, *parts: bytes) -> bytes:
    return hmac_sha3_256_bits(
        key,
        [(part, len(part) * 8) for part in parts],
    )


def _derive_keys(key: bytes) -> tuple[bytes, bytes, bytes]:
    def derive(purpose: int) -> bytes:
        return _hmac_bytes(key, _KDF_LABEL, bytes((purpose, len(key))))

    return derive(0x01)[:len(key)], derive(0x02), derive(0x03)


def _u64be(value: int) -> bytes:
    return value.to_bytes(8, "big")


def _core_hmac(
    hash_key: bytes, tail: bytes, domain: int, tweak: bytes
) -> bytes:
    return _hmac_bytes(
        hash_key,
        _CORE_LABEL,
        bytes((domain,)),
        _u64be(len(tail)),
        _u64be(len(tweak)),
        tail,
        tweak,
    )


def _ctr(aes, seed: bytes, length: int) -> tuple[bytes, list[dict[str, object]]]:
    output = bytearray()
    blocks = []
    for index in range((length + 15) // 16):
        encoded = index.to_bytes(16, "big")
        counter = _xor(seed, encoded)
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
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    if len(tweak) not in VALID_TWEAK_BYTES:
        raise ValueError(
            "Animagus tweaks must be empty or exactly 16 bytes; "
            "derive them with derive_tweak()"
        )
    _validate_message_length(len(message))


def derive_tweak(key: bytes, nonce: bytes, ad: bytes = b"") -> bytes:
    """Derive the v1 accordion tweak from framed nonce and associated data."""
    if len(key) not in VALID_KEY_BYTES:
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    _, _, tweak_key = _derive_keys(key)
    return _hmac_bytes(
        tweak_key,
        _TWEAK_LABEL,
        _u64be(len(nonce)),
        _u64be(len(ad)),
        nonce,
        ad,
    )[:TWEAK_BYTES]


def _trace(
    x1: bytes,
    a1: bytes,
    a2: bytes,
    f: bytes,
    b: bytes,
    j: bytes,
    counter_blocks: list[dict[str, object]],
    x2: bytes,
    a3: bytes,
    a4: bytes,
    c1: bytes,
    c2: bytes,
) -> dict[str, object]:
    return {
        "X1": x1.hex(),
        "A1": a1.hex(),
        "A2": a2.hex(),
        "F": f.hex(),
        "B": b.hex(),
        "J": j.hex(),
        "counter_blocks": counter_blocks,
        "X2": x2.hex(),
        "A3": a3.hex(),
        "A4": a4.hex(),
        "C1": c1.hex(),
        "C2": c2.hex(),
    }


def encrypt(
    key: bytes, tweak: bytes, plaintext: bytes, trace: bool = False
) -> bytes | tuple[bytes, dict[str, object]]:
    """Encrypt with the repository's Animagus-AES-v1 profile."""
    _validate(key, tweak, plaintext)
    aes_key, hash_key, _ = _derive_keys(key)
    aes = AES.new(aes_key, AES.MODE_ECB)
    p1, p2, p_tail = plaintext[:16], plaintext[16:32], plaintext[32:]

    x1 = _core_hmac(hash_key, p_tail, _PLAINTEXT_DOMAIN, tweak)
    a1, a2 = x1[:16], x1[16:]
    f = aes.encrypt(_xor(p1, a2))
    b = aes.encrypt(_xor(_xor(p2, a1), f))
    j = _xor(f, b)
    stream, counter_blocks = _ctr(aes, j, len(p_tail))
    c_tail = _xor(p_tail, stream)
    x2 = _core_hmac(hash_key, c_tail, _CIPHERTEXT_DOMAIN, tweak)
    a3, a4 = x2[:16], x2[16:]
    c2 = aes.encrypt(_xor(b, a3))
    c1 = aes.encrypt(_xor(_xor(f, a4), c2))
    ciphertext = c1 + c2 + c_tail

    if not trace:
        return ciphertext
    return ciphertext, _trace(
        x1, a1, a2, f, b, j, counter_blocks, x2, a3, a4, c1, c2
    )


def decrypt(
    key: bytes, tweak: bytes, ciphertext: bytes, trace: bool = False
) -> bytes | tuple[bytes, dict[str, object]]:
    """Decrypt with the repository's Animagus-AES-v1 profile."""
    _validate(key, tweak, ciphertext)
    aes_key, hash_key, _ = _derive_keys(key)
    aes = AES.new(aes_key, AES.MODE_ECB)
    c1, c2, c_tail = ciphertext[:16], ciphertext[16:32], ciphertext[32:]

    x1 = _core_hmac(hash_key, c_tail, _CIPHERTEXT_DOMAIN, tweak)
    a1, a2 = x1[:16], x1[16:]
    f = _xor(_xor(aes.decrypt(c1), a2), c2)
    b = _xor(aes.decrypt(c2), a1)
    j = _xor(f, b)
    stream, counter_blocks = _ctr(aes, j, len(c_tail))
    p_tail = _xor(c_tail, stream)
    x2 = _core_hmac(hash_key, p_tail, _PLAINTEXT_DOMAIN, tweak)
    a3, a4 = x2[:16], x2[16:]
    p2 = _xor(_xor(aes.decrypt(b), a3), f)
    p1 = _xor(aes.decrypt(f), a4)
    plaintext = p1 + p2 + p_tail

    if not trace:
        return plaintext
    return plaintext, _trace(
        x1, a1, a2, f, b, j, counter_blocks, x2, a3, a4, c1, c2
    )
