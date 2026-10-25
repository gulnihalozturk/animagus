import hashlib
import hmac
import json
import pathlib
import unittest
from unittest import mock

from python import animagus
from python.animagus import (
    APPLICATION_AEAD,
    APPLICATION_DAE,
    APPLICATION_TWEAKABLE,
    AUTH_BLOCK,
    AuthenticationError,
    aead_decrypt,
    aead_encrypt,
    dae_decrypt,
    dae_encrypt,
    decrypt,
    derive_tweak,
    derive_working_keys,
    encrypt,
    make_tweak,
    tweakable_decrypt,
    tweakable_encrypt,
)
from python.sha3_bits import hmac_sha3_256_bits


TWEAK = bytes((i * 17 + 5) & 0xFF for i in range(16))


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
        ciphertext, trace = encrypt(key, TWEAK, plaintext, trace=True)
        self.assertEqual(trace["counter_blocks"], [])
        self.assertEqual(decrypt(key, TWEAK, ciphertext), plaintext)

    def test_decrypt_trace_matches_encrypt_trace(self):
        key = bytes(range(24))
        plaintext = bytes((i * 13 + 7) & 0xFF for i in range(49))
        ciphertext, encrypt_trace = encrypt(key, TWEAK, plaintext, trace=True)
        recovered, decrypt_trace = decrypt(key, TWEAK, ciphertext, trace=True)
        self.assertEqual(recovered, plaintext)
        self.assertEqual(decrypt_trace, encrypt_trace)
        self.assertEqual(len(encrypt_trace["counter_blocks"]), 2)

    def test_mixed_head_values_preserve_xor(self):
        key = bytes(range(32))
        _, trace = encrypt(key, TWEAK, bytes(range(40)), trace=True)
        f = bytes.fromhex(trace["F"])
        b = bytes.fromhex(trace["B"])
        f_star = bytes.fromhex(trace["F_star"])
        b_star = bytes.fromhex(trace["B_star"])
        j = bytes.fromhex(trace["J"])
        self.assertEqual(animagus._xor(f, j), f_star)
        self.assertEqual(animagus._xor(b, j), b_star)
        self.assertEqual(animagus._xor(f, b), animagus._xor(f_star, b_star))

    def test_rejects_invalid_lengths(self):
        with self.assertRaises(ValueError):
            encrypt(bytes(16), TWEAK, bytes(31))
        with self.assertRaises(ValueError):
            decrypt(bytes(16), TWEAK, bytes(31))
        with self.assertRaises(ValueError):
            encrypt(bytes(15), TWEAK, bytes(32))

    def test_rejects_invalid_tweak_lengths(self):
        for tweak_len in (0, 1, 15, 17, 32, 47):
            with self.assertRaises(ValueError):
                encrypt(bytes(16), bytes(tweak_len), bytes(32))
            with self.assertRaises(ValueError):
                decrypt(bytes(16), bytes(tweak_len), bytes(32))

    def test_working_keys_follow_sp800_108_counter_mode(self):
        for key_len in (16, 24, 32):
            key = bytes(range(100, 100 + key_len))
            keys = derive_working_keys(key)
            self.assertEqual(
                list(keys), ["head1", "head2", "seed", "ctr", "hash"]
            )
            for role, value in keys.items():
                fixed_input = (
                    b"\x00\x00\x00\x01"
                    + b"animagus/" + role.encode("ascii")
                    + b"\x00"
                    + (8 * key_len).to_bytes(4, "big")
                )
                expected = hmac.new(key, fixed_input, hashlib.sha3_256).digest()
                self.assertEqual(value, expected[:key_len])
                self.assertEqual(len(value), key_len)
            self.assertEqual(len(set(keys.values())), 5)

    def test_core_hash_uses_literal_two_bit_role_codes(self):
        key = bytes(range(16))
        plaintext = bytes(range(32)) + b"\xaa\xbb\xcc"
        ciphertext, trace = encrypt(key, TWEAK, plaintext, trace=True)
        hash_key = derive_working_keys(key)["hash"]
        expected_x1 = hmac_sha3_256_bits(
            hash_key, [(plaintext[32:], 24), (b"\x01", 2), (TWEAK, 128)]
        )
        expected_x2 = hmac_sha3_256_bits(
            hash_key, [(ciphertext[32:], 24), (b"\x02", 2), (TWEAK, 128)]
        )
        self.assertEqual(trace["X1"], expected_x1.hex())
        self.assertEqual(trace["X2"], expected_x2.hex())
        # Same tail and tweak under the two role codes give different masks:
        # only the two role bits differ between these inputs.
        same_tail = plaintext[32:]
        self.assertNotEqual(
            hmac_sha3_256_bits(
                hash_key, [(same_tail, 24), (bytes([1]), 2), (TWEAK, 128)]
            ),
            hmac_sha3_256_bits(
                hash_key, [(same_tail, 24), (bytes([2]), 2), (TWEAK, 128)]
            ),
        )

    def test_derive_tweak_matches_make_tweak_frame(self):
        key = bytes(range(32))
        nonce = bytes(range(12))
        ad = bytes(range(64, 91))
        hash_key = derive_working_keys(key)["hash"]
        framed = b"\x01" + (8 * len(nonce)).to_bytes(8, "big") + nonce + ad
        expected = hmac_sha3_256_bits(
            hash_key,
            [(framed, 8 * len(framed)), (b"\x00", 2), (bytes(16), 128)],
        )[:16]
        self.assertEqual(make_tweak(key, APPLICATION_AEAD, nonce, ad), expected)

    def test_derive_tweak_encodes_nonce_length_in_bits(self):
        key = bytes(range(16))
        hash_key = derive_working_keys(key)["hash"]
        framed = b"\x01" + (16).to_bytes(8, "big") + b"\x01\x02"
        expected = hmac_sha3_256_bits(
            hash_key,
            [(framed, 8 * len(framed)), (b"\x00", 2), (bytes(16), 128)],
        )[:16]
        self.assertEqual(make_tweak(key, APPLICATION_AEAD, b"\x01\x02"), expected)

    def test_derive_tweak_encodes_nonce_ad_boundary(self):
        key = bytes(range(16))
        self.assertNotEqual(
            make_tweak(key, APPLICATION_AEAD, b"\x01\x02", b"\x03"),
            make_tweak(key, APPLICATION_AEAD, b"\x01", b"\x02\x03"),
        )

    def test_derive_tweak_separates_applications(self):
        key = bytes(range(16))
        self.assertNotEqual(
            make_tweak(key, APPLICATION_TWEAKABLE),
            make_tweak(key, APPLICATION_DAE),
        )
        self.assertEqual(
            make_tweak(key, APPLICATION_DAE), make_tweak(key, APPLICATION_DAE)
        )

    def test_derive_tweak_enforces_interface_shapes(self):
        key = bytes(range(16))
        with self.assertRaises(ValueError):
            make_tweak(key, APPLICATION_AEAD, b"", b"ad")
        with self.assertRaises(ValueError):
            make_tweak(key, APPLICATION_TWEAKABLE, b"nonce", b"")
        with self.assertRaises(ValueError):
            make_tweak(key, APPLICATION_DAE, b"", b"context")
        with self.assertRaises(ValueError):
            make_tweak(key, 0, b"nonce")
        with self.assertRaises(ValueError):
            make_tweak(key, 4, b"nonce")
        with self.assertRaises(ValueError):
            make_tweak(bytes(15), APPLICATION_AEAD, bytes(12))

    def test_derived_tweak_round_trip(self):
        key = bytes(range(16, 48))
        tweak = make_tweak(key, APPLICATION_AEAD, bytes(range(12)), b"header")
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
                encrypt(bytes(16), TWEAK, _OversizedMessage())

    def test_decrypt_rejects_oversized_message_before_access(self):
        with mock.patch.object(
            animagus.AES,
            "new",
            side_effect=AssertionError("AES was initialized"),
        ):
            with self.assertRaises(ValueError):
                decrypt(bytes(16), TWEAK, _OversizedMessage())

    def test_aead_round_trip_matches_core_composition(self):
        key = bytes(range(32))
        nonce = bytes(range(12))
        ad = b"associated data"
        message = bytes((i * 11 + 1) & 0xFF for i in range(40))
        ciphertext = aead_encrypt(key, nonce, ad, message)
        self.assertEqual(len(ciphertext), len(message) + 16)
        tweak = make_tweak(key, APPLICATION_AEAD, nonce, ad)
        self.assertEqual(ciphertext, encrypt(key, tweak, AUTH_BLOCK + message))
        self.assertEqual(aead_decrypt(key, nonce, ad, ciphertext), message)

    def test_aead_rejects_tampering(self):
        key = bytes(range(16))
        nonce = b"\x01" * 12
        ad = b"ad"
        message = bytes(range(20))
        ciphertext = aead_encrypt(key, nonce, ad, message)
        for position in (0, 15, 16, 31, 32, len(ciphertext) - 1):
            tampered = bytearray(ciphertext)
            tampered[position] ^= 0x01
            with self.assertRaises(AuthenticationError):
                aead_decrypt(key, nonce, ad, bytes(tampered))
        with self.assertRaises(AuthenticationError):
            aead_decrypt(key, b"\x02" * 12, ad, ciphertext)
        with self.assertRaises(AuthenticationError):
            aead_decrypt(key, nonce, b"ax", ciphertext)
        with self.assertRaises(AuthenticationError):
            aead_decrypt(key, nonce, b"", ciphertext)
        with self.assertRaises(AuthenticationError):
            aead_decrypt(key, nonce + b"\x00", ad, ciphertext)

    def test_aead_requires_nonempty_nonce(self):
        with self.assertRaises(ValueError):
            aead_encrypt(bytes(16), b"", b"", bytes(16))

    def test_dae_is_deterministic_and_matches_core_composition(self):
        key = bytes(range(24))
        message = bytes(range(16))
        ciphertext = dae_encrypt(key, message)
        self.assertEqual(dae_encrypt(key, message), ciphertext)
        tweak = make_tweak(key, APPLICATION_DAE)
        self.assertEqual(ciphertext, encrypt(key, tweak, AUTH_BLOCK + message))
        self.assertEqual(dae_decrypt(key, ciphertext), message)
        tampered = bytearray(ciphertext)
        tampered[5] ^= 0x40
        with self.assertRaises(AuthenticationError):
            dae_decrypt(key, bytes(tampered))

    def test_tweakable_matches_core_composition(self):
        key = bytes(range(16))
        context = b"context"
        plaintext = bytes(range(48))
        ciphertext = tweakable_encrypt(key, context, plaintext)
        tweak = make_tweak(key, APPLICATION_TWEAKABLE, b"", context)
        self.assertEqual(ciphertext, encrypt(key, tweak, plaintext))
        self.assertEqual(tweakable_decrypt(key, context, ciphertext), plaintext)
        self.assertNotEqual(tweakable_encrypt(key, b"", plaintext), ciphertext)
        # No authentication: another context decrypts to garbage, not an error.
        self.assertNotEqual(tweakable_decrypt(key, b"other", ciphertext), plaintext)

    def test_authenticated_length_bounds(self):
        animagus._validate_derived_message_length(16)
        animagus._validate_derived_message_length((1 << 52) - 16)
        for invalid_length in (0, 15, (1 << 52) - 15):
            with self.assertRaises(ValueError):
                animagus._validate_derived_message_length(invalid_length)
        # Length errors must be length errors, not authentication failures.
        with self.assertRaisesRegex(ValueError, "must be at least 16"):
            aead_encrypt(bytes(16), b"n", b"", bytes(15))
        with self.assertRaisesRegex(ValueError, "must be at least 16"):
            dae_encrypt(bytes(16), bytes(15))
        with self.assertRaisesRegex(ValueError, "must be at least 32"):
            dae_decrypt(bytes(16), bytes(31))
        with self.assertRaisesRegex(ValueError, "must be at least 32"):
            aead_decrypt(bytes(16), b"n", b"", bytes(31))
        # And the length check precedes the nonce-shape check, as in C.
        with self.assertRaisesRegex(ValueError, "must be at least 16"):
            aead_encrypt(bytes(16), b"", b"", bytes(15))

    def test_public_derive_tweak_is_the_tweakable_form(self):
        key = bytes(range(16))
        for context in (b"", b"c", bytes(range(200))):
            self.assertEqual(
                derive_tweak(key, context),
                make_tweak(key, APPLICATION_TWEAKABLE, b"", context),
            )
        self.assertEqual(derive_tweak(key), derive_tweak(key, b""))

    def test_all_repository_vectors(self):
        vector_dir = (
            pathlib.Path(__file__).resolve().parents[1]
            / "test_vectors/ours/Animagus"
        )
        paths = sorted(vector_dir.glob("Animagus_AES*.json"))
        self.assertEqual(len(paths), 3)
        for path in paths:
            vectors = json.loads(path.read_text(encoding="ascii"))
            self.assertEqual(vectors["profile"], "Animagus-AES-v2")
            self.assertEqual(vectors["profile_version"], 2)
            self.assertIs(vectors["normative"], True)
            self.assertEqual(len(vectors["cases"]), 9)
            self.assertEqual(len(vectors["tweak_cases"]), 12)
            self.assertEqual(len(vectors["aead_cases"]), 7)
            self.assertEqual(len(vectors["dae_cases"]), 6)
            self.assertEqual(len(vectors["tweakable_cases"]), 3)
            self.assertEqual(
                sorted(
                    len(bytes.fromhex(case["plaintext"]))
                    for case in vectors["cases"]
                ),
                [32, 33, 47, 48, 49, 64, 167, 512, 4096],
            )
            # At least one MakeTweak input spans a SHA3 rate block.
            self.assertTrue(any(
                9 + len(bytes.fromhex(case["nonce"]))
                + len(bytes.fromhex(case["ad"])) > 136
                for case in vectors["tweak_cases"]
            ))
            for index, case in enumerate(vectors["aead_cases"]):
                with self.subTest(file=path.name, aead_case=index):
                    key = bytes.fromhex(case["key"])
                    nonce = bytes.fromhex(case["nonce"])
                    ad = bytes.fromhex(case["ad"])
                    message = bytes.fromhex(case["message"])
                    ciphertext = bytes.fromhex(case["ciphertext"])
                    self.assertEqual(len(ciphertext), len(message) + 16)
                    self.assertEqual(aead_encrypt(key, nonce, ad, message), ciphertext)
                    self.assertEqual(aead_decrypt(key, nonce, ad, ciphertext), message)
            for index, case in enumerate(vectors["dae_cases"]):
                with self.subTest(file=path.name, dae_case=index):
                    key = bytes.fromhex(case["key"])
                    message = bytes.fromhex(case["message"])
                    ciphertext = bytes.fromhex(case["ciphertext"])
                    self.assertEqual(dae_encrypt(key, message), ciphertext)
                    self.assertEqual(dae_decrypt(key, ciphertext), message)
            for index, case in enumerate(vectors["tweakable_cases"]):
                with self.subTest(file=path.name, tweakable_case=index):
                    key = bytes.fromhex(case["key"])
                    context = bytes.fromhex(case["context"])
                    plaintext = bytes.fromhex(case["plaintext"])
                    ciphertext = bytes.fromhex(case["ciphertext"])
                    self.assertEqual(
                        tweakable_encrypt(key, context, plaintext), ciphertext
                    )
                    self.assertEqual(
                        tweakable_decrypt(key, context, ciphertext), plaintext
                    )
            for index, case in enumerate(vectors["tweak_cases"]):
                with self.subTest(file=path.name, tweak_case=index):
                    self.assertEqual(
                        make_tweak(
                            bytes.fromhex(case["key"]),
                            case["application"],
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
                    self.assertEqual(len(tweak), 16)
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
