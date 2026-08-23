"""Independent bit-oriented SHA3-256 and HMAC-SHA3-256 oracle."""

MASK64 = (1 << 64) - 1
RATE_BITS = 1088
RATE_BYTES = RATE_BITS // 8
OUTPUT_BYTES = 32

ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082,
    0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B,
    0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080,
    0x0000000080000001, 0x8000000080008008,
)

ROTATION = (
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14,
)


def _rol64(value: int, shift: int) -> int:
    if shift == 0:
        return value & MASK64
    return ((value << shift) | (value >> (64 - shift))) & MASK64


def _keccak_f1600(state: list[int]) -> None:
    for rc in ROUND_CONSTANTS:
        parity = [
            state[x] ^ state[x + 5] ^ state[x + 10] ^
            state[x + 15] ^ state[x + 20]
            for x in range(5)
        ]
        delta = [
            parity[(x - 1) % 5] ^ _rol64(parity[(x + 1) % 5], 1)
            for x in range(5)
        ]
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] ^= delta[x]

        moved = [0] * 25
        for y in range(5):
            for x in range(5):
                moved[y + 5 * ((2 * x + 3 * y) % 5)] = _rol64(
                    state[x + 5 * y], ROTATION[x + 5 * y]
                )

        for y in range(5):
            row = moved[5 * y:5 * y + 5]
            for x in range(5):
                state[x + 5 * y] = (
                    row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5])
                ) & MASK64
        state[0] ^= rc


class Sha3_256:
    """Incremental SHA3-256 sponge accepting little-endian bit strings."""

    def __init__(self) -> None:
        self._state = [0] * 25
        self._position = 0
        self._finalized = False

    def _absorb_bit(self, bit: int) -> None:
        if bit:
            self._state[self._position // 64] ^= 1 << (self._position % 64)
        self._position += 1
        if self._position == RATE_BITS:
            _keccak_f1600(self._state)
            self._position = 0

    def update_bits(self, data: bytes, bit_length: int) -> "Sha3_256":
        if self._finalized:
            raise ValueError("cannot update a finalized hash")
        if bit_length < 0 or bit_length > len(data) * 8:
            raise ValueError("bit_length must fit within data")
        for i in range(bit_length):
            self._absorb_bit((data[i // 8] >> (i % 8)) & 1)
        return self

    def digest(self) -> bytes:
        if self._finalized:
            raise ValueError("digest already requested")
        self._finalized = True
        for bit in (0, 1, 1):
            self._absorb_bit(bit)
        while self._position != RATE_BITS - 1:
            self._absorb_bit(0)
        self._absorb_bit(1)
        return b"".join(self._state[lane].to_bytes(8, "little") for lane in range(4))


def sha3_256_bits(message: bytes, bit_length: int) -> bytes:
    return Sha3_256().update_bits(message, bit_length).digest()


def hmac_sha3_256_bits(key: bytes, segments: list[tuple[bytes, int]]) -> bytes:
    if len(key) > RATE_BYTES:
        key = sha3_256_bits(key, len(key) * 8)
    key_block = key.ljust(RATE_BYTES, b"\x00")
    inner = Sha3_256().update_bits(bytes(value ^ 0x36 for value in key_block), RATE_BITS)
    for data, bit_length in segments:
        inner.update_bits(data, bit_length)
    inner_digest = inner.digest()
    outer = Sha3_256().update_bits(bytes(value ^ 0x5C for value in key_block), RATE_BITS)
    return outer.update_bits(inner_digest, OUTPUT_BYTES * 8).digest()
