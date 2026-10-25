import hashlib
import hmac
import pathlib
import unittest

from python.sha3_bits import hmac_sha3_256_bits, sha3_256_bits

ROOT = pathlib.Path(__file__).resolve().parents[1]
VECTORS = ROOT / "test_vectors/external/nist/SHA3_256_selected_bit_vectors.txt"
FULL_VECTORS = ROOT / "test_vectors/external/nist/SHA3_256ShortMsg.rsp"


def _parse_rsp(path: pathlib.Path) -> list[dict[str, str]]:
    cases = []
    current = {}
    for line in path.read_text(encoding="ascii").splitlines():
        if " = " in line and not line.startswith("#"):
            key, value = line.split(" = ", 1)
            current[key.strip()] = value.strip()
        if "MD" in current:
            cases.append(current)
            current = {}
    return cases


class Sha3BitsTests(unittest.TestCase):
    def test_byte_aligned_sha3_matches_hashlib(self):
        for message in (b"", b"abc", bytes(range(256))):
            self.assertEqual(
                sha3_256_bits(message, len(message) * 8),
                hashlib.sha3_256(message).digest(),
            )

    def test_selected_nist_bit_vectors(self):
        cases = _parse_rsp(VECTORS)
        self.assertEqual(len(cases), 6)
        for case in cases:
            message = bytes.fromhex(case["Msg"])
            expected = bytes.fromhex(case["MD"])
            self.assertEqual(sha3_256_bits(message, int(case["Len"])), expected)

    def test_full_nist_bit_oriented_short_messages(self):
        # Every bit length from 0 through 1088: all partial-byte positions
        # and the rate boundary, in the CAVS bit-oriented convention.
        cases = _parse_rsp(FULL_VECTORS)
        self.assertEqual(len(cases), 1089)
        self.assertEqual(
            sorted(int(case["Len"]) for case in cases), list(range(1089))
        )
        for case in cases:
            message = bytes.fromhex(case["Msg"])
            expected = bytes.fromhex(case["MD"])
            self.assertEqual(sha3_256_bits(message, int(case["Len"])), expected)

    def test_byte_aligned_hmac_matches_standard_library(self):
        cases = (
            (bytes.fromhex("0b" * 20), b"Hi There"),
            (b"Jefe", b"what do ya want for nothing?"),
            (bytes.fromhex("aa" * 20), bytes.fromhex("dd" * 50)),
        )
        for key, message in cases:
            expected = hmac.new(key, message, hashlib.sha3_256).digest()
            actual = hmac_sha3_256_bits(key, [(message, len(message) * 8)])
            self.assertEqual(actual, expected)

if __name__ == "__main__":
    unittest.main()
