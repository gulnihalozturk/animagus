#include "hmac_sha3.h"
#include "hmac_sha3_animagus_v1_testvecs.h"
#include "test_common.h"

#include <stdint.h>

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

static void check_profile_vectors(void)
{
    size_t index;

    for (index = 0;
         index < sizeof(hmac_sha3_animagus_v1_testvecs) /
                 sizeof(hmac_sha3_animagus_v1_testvecs[0]);
         ++index) {
        const struct hmac_sha3_animagus_v1_testvec *vector =
            &hmac_sha3_animagus_v1_testvecs[index];
        struct hmac_sha3_256_ctx ctx;
        uint8_t actual[32];

        ASSERT_EQ(hmac_sha3_256_init(&ctx, vector->key.data,
                                     vector->key.len), 0U);
        hmac_sha3_256_animagus_v1(
            &ctx, vector->tail.data, vector->tail.len,
            ANIMAGUS_HASH_PLAINTEXT,
            vector->tweak.data, vector->tweak.len, actual);
        ASSERT_EQ(vector->plaintext_digest.len, sizeof(actual));
        ASSERT_MEMEQ(actual, vector->plaintext_digest.data, sizeof(actual));

        hmac_sha3_256_animagus_v1(
            &ctx, vector->tail.data, vector->tail.len,
            ANIMAGUS_HASH_CIPHERTEXT,
            vector->tweak.data, vector->tweak.len, actual);
        ASSERT_EQ(vector->ciphertext_digest.len, sizeof(actual));
        ASSERT_MEMEQ(actual, vector->ciphertext_digest.data, sizeof(actual));
    }
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
    check_profile_vectors();
    check_key_boundaries_and_null_key();
    check_bytes2_matches_concatenation();
    return 0;
}
