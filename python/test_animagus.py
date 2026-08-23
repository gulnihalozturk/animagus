import hashlib
import hmac
import json
import pathlib
import unittest
from unittest import mock

from python import animagus
from python.animagus import decrypt, derive_tweak, encrypt


class _OversizedMessage(bytes):
    def __len__(self) -> int:
        return (1 << 52) + 1

    def __getitem__(self, index):
        raise AssertionError("oversized message contents were accessed")


class AnimagusTests(unittest.TestCase):
    def test_round_trip_all_key_and_boundary_lengths(self):
        for key_len in (16, 24, 32):
            key = bytes(range(key_len))
            for message_len in (32, 33, 47, 48, 49, 64, 512):
                plaintext = bytes((i * 29 + message_len) & 0xFF
                                  for i in range(message_len))
                tweak = bytes((i * 17 + key_len) & 0xFF for i in range(16))
                ciphertext = encrypt(key, tweak, plaintext)
                self.assertEqual(len(ciphertext), len(plaintext))
                self.assertNotEqual(ciphertext, plaintext)
                self.assertEqual(decrypt(key, tweak, ciphertext), plaintext)

    def test_exactly_two_blocks_uses_no_ctr_blocks(self):
        key = bytes(range(16))
        plaintext = bytes(range(32))
        ciphertext, trace = encrypt(key, b"", plaintext, trace=True)
        self.assertEqual(trace["counter_blocks"], [])
        self.assertEqual(decrypt(key, b"", ciphertext), plaintext)

    def test_rejects_invalid_lengths(self):
        with self.assertRaises(ValueError):
            encrypt(bytes(16), b"", bytes(31))
        with self.assertRaises(ValueError):
            decrypt(bytes(16), b"", bytes(31))
        with self.assertRaises(ValueError):
            encrypt(bytes(15), b"", bytes(32))

    def test_rejects_invalid_tweak_lengths(self):
        for tweak_len in (1, 15, 17, 32, 47):
            with self.assertRaises(ValueError):
                encrypt(bytes(16), bytes(tweak_len), bytes(32))
            with self.assertRaises(ValueError):
                decrypt(bytes(16), bytes(tweak_len), bytes(32))

    def test_derive_tweak_uses_v1_key_and_length_framing(self):
        key = bytes(range(32))
        nonce = bytes(range(12))
        ad = bytes(range(64, 91))
        tweak_key = hmac.new(
            key,
            b"Animagus-AES-v1/KDF" + bytes((0x03, len(key))),
            hashlib.sha3_256,
        ).digest()
        framed = (
            b"Animagus-AES-v1/TWEAK"
            + len(nonce).to_bytes(8, "big")
            + len(ad).to_bytes(8, "big")
            + nonce
            + ad
        )
        expected = hmac.new(tweak_key, framed, hashlib.sha3_256).digest()[:16]
        self.assertEqual(derive_tweak(key, nonce, ad), expected)
        self.assertEqual(len(derive_tweak(key, nonce)), 16)

    def test_derive_tweak_encodes_nonce_ad_boundary(self):
        key = bytes(range(16))
        self.assertNotEqual(
            derive_tweak(key, b"\x01\x02", b"\x03"),
            derive_tweak(key, b"\x01", b"\x02\x03"),
        )

    def test_empty_and_nonempty_tweak_domains_do_not_share_old_frame(self):
        key = bytes(16)
        short = bytes(32) + b"\x00"
        long = bytes(32) + b"\x00\x01" + bytes(15)
        tweak = bytes(15) + b"\x40"
        self.assertNotEqual(
            encrypt(key, tweak, short)[32],
            encrypt(key, b"", long)[32],
        )

    def test_derive_tweak_rejects_invalid_key(self):
        with self.assertRaises(ValueError):
            derive_tweak(bytes(15), bytes(12))

    def test_derived_tweak_round_trip(self):
        key = bytes(range(16, 48))
        tweak = derive_tweak(key, bytes(range(12)), b"header")
        plaintext = bytes((i * 7 + 3) & 0xFF for i in range(50))
        ciphertext = encrypt(key, tweak, plaintext)
        self.assertEqual(decrypt(key, tweak, ciphertext), plaintext)

    def test_length_validator_enforces_profile_boundaries(self):
        animagus._validate_message_length(32)
        animagus._validate_message_length(1 << 52)
        for invalid_length in (31, (1 << 52) + 1):
            with self.assertRaises(ValueError):
                animagus._validate_message_length(invalid_length)

    def test_encrypt_rejects_oversized_message_before_access(self):
        with mock.patch.object(
            animagus.AES,
            "new",
            side_effect=AssertionError("AES was initialized"),
        ):
            with self.assertRaises(ValueError):
                encrypt(bytes(16), b"", _OversizedMessage())

    def test_decrypt_rejects_oversized_message_before_access(self):
        with mock.patch.object(
            animagus.AES,
            "new",
            side_effect=AssertionError("AES was initialized"),
        ):
            with self.assertRaises(ValueError):
                decrypt(bytes(16), b"", _OversizedMessage())

    def test_all_repository_vectors(self):
        vector_dir = (
            pathlib.Path(__file__).resolve().parents[1]
            / "test_vectors/ours/Animagus"
        )
        paths = sorted(vector_dir.glob("Animagus_AES*.json"))
        self.assertEqual(len(paths), 3)
        for path in paths:
            vectors = json.loads(path.read_text(encoding="ascii"))
            self.assertEqual(vectors["profile"], "Animagus-AES-v1")
            self.assertEqual(vectors["profile_version"], 1)
            self.assertIs(vectors["normative"], True)
            self.assertEqual(len(vectors["cases"]), 16)
            self.assertEqual(len(vectors["tweak_cases"]), 6)
            for index, case in enumerate(vectors["tweak_cases"]):
                with self.subTest(file=path.name, tweak_case=index):
                    self.assertEqual(
                        derive_tweak(
                            bytes.fromhex(case["key"]),
                            bytes.fromhex(case["nonce"]),
                            bytes.fromhex(case["ad"]),
                        ),
                        bytes.fromhex(case["tweak"]),
                    )
            for index, case in enumerate(vectors["cases"]):
                with self.subTest(file=path.name, case=index):
                    key = bytes.fromhex(case["key"])
                    tweak = bytes.fromhex(case["tweak"])
                    plaintext = bytes.fromhex(case["plaintext"])
                    expected_ciphertext = bytes.fromhex(case["ciphertext"])
                    if "trace" in case:
                        ciphertext, trace = encrypt(
                            key, tweak, plaintext, trace=True
                        )
                        self.assertEqual(trace, case["trace"])
                    else:
                        ciphertext = encrypt(key, tweak, plaintext)
                    self.assertEqual(ciphertext, expected_ciphertext)
                    self.assertEqual(
                        decrypt(key, tweak, expected_ciphertext), plaintext
                    )


if __name__ == "__main__":
    unittest.main()
