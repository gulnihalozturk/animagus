#include "hmac_sha3.h"
#include "hmac_sha3_animagus_v2_testvecs.h"
#include "test_common.h"

#include <stdint.h>
#include <string.h>

struct hmac_vector {
    const char *key_hex;
    const char *message_hex;
    const char *digest_hex;
};

struct hmac_key_boundary_vector {
    size_t key_len;
    const char *digest_hex;
};

static const struct hmac_vector standard_vectors[] = {
    {
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "4869205468657265",
        "ba85192310dffa96e2a3a40e697743511"
        "40bb7185e1202cdcc917589f95e16bb"
    },
    {
        "4a656665",
        "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
        "c7d4072e788877ae3596bbb0da73b887c"
        "9171f93095b294ae857fbe2645e1ba5"
    },
    {
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        "dddddddddddddddddddddddddddddddddddddddd",
        "84ec79124a27107865cedd8bd82da9965"
        "e5ed8c37b0ac98005a7f39ed58a4207"
    },
};

static const struct hmac_key_boundary_vector key_boundary_vectors[] = {
    {0, "bf734bb79cfad254a5b64f7d900542b8"
        "ea40188a7423a8b0cf35236ba6a81458"},
    {135, "6e5e4d2cb66d9210f55cd55c87dae105"
          "bf951b5f9490db0254137e6bfdcc0dd7"},
    {136, "059585bd272f583a5ca2efed32c932fb"
          "c4a38cb5216340e8c472e8708d128de5"},
    {137, "b520d29a466609fd95fe2656594c999b"
          "d40f08a472b4ec78e5150a0ee8f0c580"},
};

static void check_standard_vectors(void)
{
    size_t index;

    for (index = 0;
         index < sizeof(standard_vectors) / sizeof(standard_vectors[0]);
         ++index) {
        uint8_t key[64], message[64], expected[32], actual[32];
        struct hmac_sha3_256_ctx ctx;
        size_t key_len = hex_decode(key, sizeof(key),
                                    standard_vectors[index].key_hex);
        size_t message_len = hex_decode(message, sizeof(message),
                                        standard_vectors[index].message_hex);

        ASSERT_EQ(hex_decode(expected, sizeof(expected),
                             standard_vectors[index].digest_hex),
                  sizeof(expected));
        ASSERT_EQ(hmac_sha3_256_init(&ctx, key, key_len), 0U);
        hmac_sha3_256_bytes(&ctx, message, message_len, actual);
        ASSERT_MEMEQ(actual, expected, sizeof(actual));
    }
}

static void check_kdf_vectors(void)
{
    static const char *const roles[] = {
        "head1", "head2", "seed", "ctr", "hash",
    };
    size_t index;

    for (index = 0;
         index < sizeof(hmac_sha3_animagus_v2_kdf_testvecs) /
                 sizeof(hmac_sha3_animagus_v2_kdf_testvecs[0]);
         ++index) {
        const struct hmac_sha3_animagus_v2_kdf_testvec *vector =
            &hmac_sha3_animagus_v2_kdf_testvecs[index];
        const struct testvec_buffer *expected[] = {
            &vector->head1, &vector->head2, &vector->seed,
            &vector->ctr, &vector->hash,
        };
        struct hmac_sha3_256_ctx root;
        uint8_t actual[32];
        size_t role;

        ASSERT_EQ(hmac_sha3_256_init(&root, vector->master_key.data,
                                     vector->master_key.len), 0U);
        for (role = 0; role < sizeof(roles) / sizeof(roles[0]); ++role) {
            ASSERT_EQ(hmac_sha3_256_kdf_v2(&root, roles[role],
                                           vector->master_key.len,
                                           actual) == 0, 1U);
            ASSERT_EQ(expected[role]->len, vector->master_key.len);
            ASSERT_MEMEQ(actual, expected[role]->data, expected[role]->len);
        }
    }
}

static void check_kdf_rejects_unknown_inputs(void)
{
    const uint8_t key[16] = { 0 };
    struct hmac_sha3_256_ctx root;
    uint8_t out[32];

    ASSERT_EQ(hmac_sha3_256_init(&root, key, sizeof(key)), 0U);
    ASSERT_EQ(hmac_sha3_256_kdf_v2(&root, "tweak", 16U, out) == -1, 1U);
    ASSERT_EQ(hmac_sha3_256_kdf_v2(&root, "", 16U, out) == -1, 1U);
    ASSERT_EQ(hmac_sha3_256_kdf_v2(&root, NULL, 16U, out) == -1, 1U);
    ASSERT_EQ(hmac_sha3_256_kdf_v2(&root, "hash", 33U, out) == -1, 1U);
    ASSERT_EQ(hmac_sha3_256_kdf_v2(&root, "hash", 32U, out), 0U);
}

static void check_core_vectors(void)
{
    size_t index;

    for (index = 0;
         index < sizeof(hmac_sha3_animagus_v2_core_testvecs) /
                 sizeof(hmac_sha3_animagus_v2_core_testvecs[0]);
         ++index) {
        const struct hmac_sha3_animagus_v2_core_testvec *vector =
            &hmac_sha3_animagus_v2_core_testvecs[index];
        struct hmac_sha3_256_ctx ctx;
        uint8_t actual[32];

        ASSERT_EQ(vector->tweak.len, ANIMAGUS_HASH_TWEAK_BYTES);
        ASSERT_EQ(hmac_sha3_256_init(&ctx, vector->key.data,
                                     vector->key.len), 0U);
        hmac_sha3_256_core_v2(&ctx, vector->tail.data, vector->tail.len,
                              ANIMAGUS_ROLE_PLAINTEXT_TAIL,
                              vector->tweak.data, actual);
        ASSERT_EQ(vector->plaintext_digest.len, sizeof(actual));
        ASSERT_MEMEQ(actual, vector->plaintext_digest.data, sizeof(actual));

        hmac_sha3_256_core_v2(&ctx, vector->tail.data, vector->tail.len,
                              ANIMAGUS_ROLE_CIPHERTEXT_TAIL,
                              vector->tweak.data, actual);
        ASSERT_EQ(vector->ciphertext_digest.len, sizeof(actual));
        ASSERT_MEMEQ(actual, vector->ciphertext_digest.data, sizeof(actual));
    }
}

static void check_tweak_vectors(void)
{
    size_t index;

    for (index = 0;
         index < sizeof(hmac_sha3_animagus_v2_tweak_testvecs) /
                 sizeof(hmac_sha3_animagus_v2_tweak_testvecs[0]);
         ++index) {
        const struct hmac_sha3_animagus_v2_tweak_testvec *vector =
            &hmac_sha3_animagus_v2_tweak_testvecs[index];
        struct hmac_sha3_256_ctx ctx;
        uint8_t actual[32];

        ASSERT_EQ(hmac_sha3_256_init(&ctx, vector->key.data,
                                     vector->key.len), 0U);
        ASSERT_EQ(hmac_sha3_256_tweak_v2(&ctx, (uint8_t)vector->application,
                                         vector->nonce.data, vector->nonce.len,
                                         vector->ad.data, vector->ad.len,
                                         actual), 0U);
        ASSERT_EQ(vector->digest.len, sizeof(actual));
        ASSERT_MEMEQ(actual, vector->digest.data, sizeof(actual));
    }
}

static void check_role_codes_and_frame_boundaries(void)
{
    const uint8_t key[16] = { 0 };
    const uint8_t tweak[ANIMAGUS_HASH_TWEAK_BYTES] = { 0 };
    const uint8_t tail[1] = { 0 };
    struct hmac_sha3_256_ctx ctx;
    uint8_t plaintext_role[32], ciphertext_role[32], tweak_role[32];
    uint8_t longer_tail[32];
    uint8_t nonce_split_a[32], nonce_split_b[32];

    ASSERT_EQ(hmac_sha3_256_init(&ctx, key, sizeof(key)), 0U);

    /* The three two-bit role codes give three different domains over the
     * same 130-bit input (empty tail, all-zero tweak): only the two role
     * bits differ between these three hashes. */
    hmac_sha3_256_core_v2(&ctx, NULL, 0U, ANIMAGUS_ROLE_PLAINTEXT_TAIL,
                          tweak, plaintext_role);
    hmac_sha3_256_core_v2(&ctx, NULL, 0U, ANIMAGUS_ROLE_CIPHERTEXT_TAIL,
                          tweak, ciphertext_role);
    hmac_sha3_256_core_v2(&ctx, NULL, 0U, ANIMAGUS_ROLE_TWEAK,
                          tweak, tweak_role);
    ASSERT_EQ(memcmp(plaintext_role, ciphertext_role, 32U) != 0, 1U);
    ASSERT_EQ(memcmp(plaintext_role, tweak_role, 32U) != 0, 1U);
    ASSERT_EQ(memcmp(ciphertext_role, tweak_role, 32U) != 0, 1U);

    /* The MakeTweak frame with d = 0 and no inputs is the byte string
     * 0x00 || BE64(0) followed by 00 || 0^128. It equals the core frame
     * over a 9-byte zero tail only under the same role code. */
    ASSERT_EQ(hmac_sha3_256_tweak_v2(&ctx, 0U, NULL, 0U, NULL, 0U,
                                     nonce_split_a), 0U);
    hmac_sha3_256_core_v2(&ctx, tweak, 9U, ANIMAGUS_ROLE_PLAINTEXT_TAIL,
                          tweak, nonce_split_b);
    ASSERT_EQ(memcmp(nonce_split_a, nonce_split_b, 32U) != 0, 1U);
    hmac_sha3_256_core_v2(&ctx, tweak, 9U, ANIMAGUS_ROLE_TWEAK,
                          tweak, nonce_split_b);
    ASSERT_MEMEQ(nonce_split_a, nonce_split_b, 32U);

    /* An empty tail and a one-byte zero tail differ in HMAC input length. */
    hmac_sha3_256_core_v2(&ctx, tail, sizeof(tail),
                          ANIMAGUS_ROLE_PLAINTEXT_TAIL, tweak, longer_tail);
    ASSERT_EQ(memcmp(plaintext_role, longer_tail, 32U) != 0, 1U);

    /* Nonce bit length delimits nonce and associated data. */
    ASSERT_EQ(hmac_sha3_256_tweak_v2(&ctx, 1U, tail, 1U, tweak, 1U,
                                     nonce_split_a), 0U);
    ASSERT_EQ(hmac_sha3_256_tweak_v2(&ctx, 1U, tail, 0U, tweak, 2U,
                                     nonce_split_b), 0U);
    ASSERT_EQ(memcmp(nonce_split_a, nonce_split_b, 32U) != 0, 1U);

#if SIZE_MAX > UINT64_C(0x1fffffffffffffff)
    ASSERT_EQ(hmac_sha3_256_tweak_v2(&ctx, 1U, tail,
                                     (size_t)ANIMAGUS_HASH_MAX_FRAMED_BYTES +
                                     1U, NULL, 0U, nonce_split_a) == -1, 1U);
    ASSERT_EQ(hmac_sha3_256_tweak_v2(&ctx, 2U, NULL, 0U, tweak,
                                     (size_t)ANIMAGUS_HASH_MAX_FRAMED_BYTES +
                                     1U, nonce_split_a) == -1, 1U);
#endif
}

static void check_key_boundaries_and_null_key(void)
{
    static const uint8_t message[] = "Animagus key boundary";
    static const char empty_digest_hex[] =
        "e841c164e5b4f10c9f3985587962af72"
        "fd607a951196fc92fb3a5251941784ea";
    uint8_t key[137], expected[32], actual[32];
    struct hmac_sha3_256_ctx ctx;
    size_t byte_index, vector_index;

    for (byte_index = 0; byte_index < sizeof(key); ++byte_index) {
        key[byte_index] = (uint8_t)byte_index;
    }
    for (vector_index = 0;
         vector_index < sizeof(key_boundary_vectors) /
                        sizeof(key_boundary_vectors[0]);
         ++vector_index) {
        ASSERT_EQ(hex_decode(expected, sizeof(expected),
                             key_boundary_vectors[vector_index].digest_hex),
                  sizeof(expected));
        ASSERT_EQ(hmac_sha3_256_init(
                      &ctx, key, key_boundary_vectors[vector_index].key_len),
                  0U);
        hmac_sha3_256_bytes(&ctx, message, sizeof(message) - 1U, actual);
        ASSERT_MEMEQ(actual, expected, sizeof(actual));
    }

    ASSERT_EQ(hmac_sha3_256_init(&ctx, NULL, 0U), 0U);
    hmac_sha3_256_bytes(&ctx, message, sizeof(message) - 1U, actual);
    ASSERT_EQ(hex_decode(expected, sizeof(expected),
                         key_boundary_vectors[0].digest_hex),
              sizeof(expected));
    ASSERT_MEMEQ(actual, expected, sizeof(actual));

    hmac_sha3_256_bytes(&ctx, NULL, 0U, actual);
    ASSERT_EQ(hex_decode(expected, sizeof(expected), empty_digest_hex),
              sizeof(expected));
    ASSERT_MEMEQ(actual, expected, sizeof(actual));
    ASSERT_EQ(hmac_sha3_256_init(&ctx, NULL, 1U) == -1, 1U);
}

static void check_bytes2_matches_concatenation(void)
{
    static const uint8_t message[] = "Animagus derive tweak segments";
    struct hmac_sha3_256_ctx ctx;
    uint8_t expected[32], actual[32];
    size_t split;

    ASSERT_EQ(hmac_sha3_256_init(&ctx, message, 16U), 0U);
    hmac_sha3_256_bytes(&ctx, message, sizeof(message) - 1U, expected);
    for (split = 0; split <= sizeof(message) - 1U; ++split) {
        hmac_sha3_256_bytes2(&ctx, message, split, message + split,
                             sizeof(message) - 1U - split, actual);
        ASSERT_MEMEQ(actual, expected, sizeof(actual));
    }
    hmac_sha3_256_bytes2(&ctx, NULL, 0U, message, sizeof(message) - 1U,
                         actual);
    ASSERT_MEMEQ(actual, expected, sizeof(actual));
    hmac_sha3_256_bytes2(&ctx, message, sizeof(message) - 1U, NULL, 0U,
                         actual);
    ASSERT_MEMEQ(actual, expected, sizeof(actual));
}

int main(void)
{
    check_standard_vectors();
    check_kdf_vectors();
    check_kdf_rejects_unknown_inputs();
    check_core_vectors();
    check_tweak_vectors();
    check_role_codes_and_frame_boundaries();
    check_key_boundaries_and_null_key();
    check_bytes2_matches_concatenation();
    return 0;
}
