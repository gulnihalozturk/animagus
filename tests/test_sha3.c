#include "sha3.h"
#include "test_common.h"

#include <stdint.h>

struct sha3_vector {
    size_t bit_len;
    const char *message_hex;
    const char *digest_hex;
};

static const struct sha3_vector vectors[] = {
    {0, "00", "a7ffc6f8bf1ed76651c14756a061d662f"
               "580ff4de43b49fa82d80a4b80f8434a"},
    {1, "00", "1b2e61923578e35f3b4629e04a0ff3b7"
               "3daa571ae01130d9c16ef7da7a4cfdc2"},
    {2, "01", "3589c95ba0b3cfc5de7c8688413fda5a"
               "2d5a55bbb106900469f6c5e4170ec959"},
    {7, "0b", "9e5f8c800689fa5168fc5fbfeca8bd5b"
               "3668ffd6f08143e2e396b9ae0f9b443e"},
    {8, "6a", "f35e560e05de779f2669b9f513c2a7ab"
               "81dfeb100e2f4ee1fb17354bfa2740ca"},
    {9, "ee01", "072805acf799dea2111dae23b89d1a244"
                  "1ebd93e1bc7cd4b13778ab1b2459947"},
};

struct sha3_byte_vector {
    size_t byte_len;
    const char *digest_hex;
};

static const struct sha3_byte_vector boundary_vectors[] = {
    {135, "fded8fd9d6551c601eeb3b7c6bc5e5c"
          "fd8aad1d015b7e9aaa9c9b9475231d5e2"},
    {136, "cf3ccff92480a29160c2d38317c430e1"
          "4749bfee1788106957dfe73f8c4930e5"},
    {137, "ce9d7dc90913ee5d92745019479a5352"
          "c6d6279bef18ed07dc0a83ee8084daca"},
    {271, "d409bcbb54825556454a757a1f629135"
          "ba49c0467dcf6b4e0aa69e9718dd31e6"},
    {272, "0b21ec4a8eff6d179e09ba9fe0ab0851"
          "5b24e0923fbf419f5c30a38e64577db5"},
};

static void check_selected_vectors(void)
{
    size_t index;

    for (index = 0; index < sizeof(vectors) / sizeof(vectors[0]); ++index) {
        uint8_t message[2], expected[SHA3_256_DIGEST_SIZE];
        uint8_t actual[SHA3_256_DIGEST_SIZE];
        struct sha3_256_ctx ctx;

        (void)hex_decode(message, sizeof(message), vectors[index].message_hex);
        ASSERT_EQ(hex_decode(expected, sizeof(expected),
                             vectors[index].digest_hex),
                  SHA3_256_DIGEST_SIZE);
        sha3_256_init(&ctx);
        sha3_256_update_bits(&ctx, message, vectors[index].bit_len);
        sha3_256_final(&ctx, actual);
        ASSERT_MEMEQ(actual, expected, sizeof(actual));

        if ((vectors[index].bit_len % 8U) == 0U) {
            size_t byte_index;

            sha3_256_init(&ctx);
            for (byte_index = 0; byte_index < vectors[index].bit_len / 8U;
                 ++byte_index) {
                sha3_256_update_bytes(&ctx, message + byte_index, 1U);
            }
            sha3_256_final(&ctx, actual);
            ASSERT_MEMEQ(actual, expected, sizeof(actual));
        }
    }
}

static void check_incremental_abc(void)
{
    static const uint8_t message[] = { 'a', 'b', 'c' };
    static const char expected_hex[] =
        "3a985da74fe225b2045c172d6bd390bd"
        "855f086e3e9d525b46bfe24511431532";
    uint8_t expected[SHA3_256_DIGEST_SIZE];
    uint8_t actual[SHA3_256_DIGEST_SIZE];
    uint8_t repeated[SHA3_256_DIGEST_SIZE];
    struct sha3_256_ctx ctx;
    size_t index;

    ASSERT_EQ(hex_decode(expected, sizeof(expected), expected_hex),
              SHA3_256_DIGEST_SIZE);
    sha3_256_init(&ctx);
    for (index = 0; index < sizeof(message); ++index) {
        sha3_256_update_bytes(&ctx, message + index, 1U);
    }
    sha3_256_final(&ctx, actual);
    sha3_256_final(&ctx, repeated);
    ASSERT_MEMEQ(actual, expected, sizeof(actual));
    ASSERT_MEMEQ(repeated, expected, sizeof(repeated));
}

static void check_rate_boundaries(void)
{
    uint8_t message[272];
    size_t byte_index, vector_index;

    for (byte_index = 0; byte_index < sizeof(message); ++byte_index) {
        message[byte_index] = (uint8_t)byte_index;
    }
    for (vector_index = 0;
         vector_index < sizeof(boundary_vectors) / sizeof(boundary_vectors[0]);
         ++vector_index) {
        uint8_t expected[SHA3_256_DIGEST_SIZE];
        uint8_t actual[SHA3_256_DIGEST_SIZE];
        struct sha3_256_ctx ctx;

        ASSERT_EQ(hex_decode(expected, sizeof(expected),
                             boundary_vectors[vector_index].digest_hex),
                  SHA3_256_DIGEST_SIZE);
        sha3_256_init(&ctx);
        sha3_256_update_bytes(&ctx, message,
                              boundary_vectors[vector_index].byte_len);
        sha3_256_final(&ctx, actual);
        ASSERT_MEMEQ(actual, expected, sizeof(actual));
    }
}

static void check_padding_crosses_rate_boundary(void)
{
    static const char expected_hex[] =
        "94a17fbcb133bdd8387119ac4ff332a9d"
        "9c0c8e87ed0f9e57595bb338feb6a2e";
    uint8_t message[SHA3_256_RATE_BYTES];
    uint8_t expected[SHA3_256_DIGEST_SIZE];
    uint8_t actual[SHA3_256_DIGEST_SIZE];
    struct sha3_256_ctx ctx;
    size_t byte_index;

    for (byte_index = 0; byte_index < sizeof(message); ++byte_index) {
        message[byte_index] = (uint8_t)byte_index;
    }
    ASSERT_EQ(hex_decode(expected, sizeof(expected), expected_hex),
              SHA3_256_DIGEST_SIZE);
    sha3_256_init(&ctx);
    sha3_256_update_bits(&ctx, message, SHA3_256_RATE_BITS - 1U);
    sha3_256_final(&ctx, actual);
    ASSERT_MEMEQ(actual, expected, sizeof(actual));
}

static void check_shifted_byte_update(void)
{
    static const uint8_t first_source = 0xee;
    static const uint8_t shifted_tail = 0xf7;
    static const char expected_hex[] =
        "072805acf799dea2111dae23b89d1a24"
        "41ebd93e1bc7cd4b13778ab1b2459947";
    uint8_t expected[SHA3_256_DIGEST_SIZE];
    uint8_t actual[SHA3_256_DIGEST_SIZE];
    struct sha3_256_ctx ctx;

    ASSERT_EQ(hex_decode(expected, sizeof(expected), expected_hex),
              SHA3_256_DIGEST_SIZE);
    sha3_256_init(&ctx);
    sha3_256_update_bits(&ctx, &first_source, 1U);
    sha3_256_update_bytes(&ctx, &shifted_tail, 1U);
    sha3_256_final(&ctx, actual);
    ASSERT_MEMEQ(actual, expected, sizeof(actual));
}

int main(void)
{
    check_selected_vectors();
    check_incremental_abc();
    check_rate_boundaries();
    check_padding_crosses_rate_boundary();
    check_shifted_byte_update();
    return 0;
}
