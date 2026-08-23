#include "aes.h"
#include "animagus_ctr.h"
#include "test_common.h"

#include <stdint.h>
#include <string.h>

static void test_counter_encoding(void)
{
    const uint8_t seed[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    uint8_t counter[16];

    animagus_ctr_counter(counter, seed, 0);
    ASSERT_MEMEQ(counter, seed, sizeof(counter));

    animagus_ctr_counter(counter, seed, 1);
    ASSERT_EQ(counter[14], 0x0e);
    ASSERT_EQ(counter[15], 0x0e);

    animagus_ctr_counter(counter, seed, UINT64_C(0x0100));
    ASSERT_EQ(counter[14], 0x0f);
    ASSERT_EQ(counter[15], 0x0f);

    animagus_ctr_counter(counter, seed, UINT64_C(0x0102030405060708));
    {
        const uint8_t expected[16] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x09, 0x0b, 0x09, 0x0f, 0x09, 0x0b, 0x09, 0x07,
        };

        ASSERT_MEMEQ(counter, expected, sizeof(counter));
    }
}

static void expected_crypt(const struct animagus_aes_ctx *ctx, uint8_t *out,
                           const uint8_t *in, size_t length,
                           const uint8_t seed[16])
{
    uint8_t counter[16], keystream[16];
    size_t offset;

    for (offset = 0; offset < length; offset += 16U) {
        size_t remaining = length - offset;
        size_t block_length = remaining < 16U ? remaining : 16U;
        size_t byte_index;

        animagus_ctr_counter(counter, seed, (uint64_t)(offset / 16U));
        animagus_aes_encrypt_block(ctx, keystream, counter);
        for (byte_index = 0; byte_index < block_length; ++byte_index) {
            out[offset + byte_index] = in[offset + byte_index] ^ keystream[byte_index];
        }
    }
}

static void test_crypt_lengths_and_in_place(void)
{
    const uint8_t key[16] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    };
    const uint8_t seed[16] = {
        0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80,
        0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x00,
    };
    const size_t lengths[] = { 0, 1, 15, 16, 17, 31, 32, 33, 127, 128, 129 };
    uint8_t input[129], expected[129], actual[129], in_place[129];
    struct animagus_aes_ctx ctx;
    size_t length_index;
    size_t index;

    for (index = 0; index < sizeof(input); ++index) {
        input[index] = (uint8_t)(index * 29U + 7U);
    }
    ASSERT_EQ(animagus_aes_setkey(&ctx, key, sizeof(key),
                                  ANIMAGUS_AES_PORTABLE), 0);

    for (length_index = 0;
         length_index < sizeof(lengths) / sizeof(lengths[0]);
         ++length_index) {
        size_t length = lengths[length_index];

        memset(expected, 0xa5, sizeof(expected));
        memset(actual, 0xa5, sizeof(actual));
        expected_crypt(&ctx, expected, input, length, seed);
        animagus_ctr_crypt(&ctx, actual, input, length, seed);
        ASSERT_MEMEQ(actual, expected, sizeof(actual));

        memcpy(in_place, input, sizeof(in_place));
        animagus_ctr_crypt(&ctx, in_place, in_place, length, seed);
        ASSERT_MEMEQ(in_place, expected, length);
        ASSERT_MEMEQ(in_place + length, input + length,
                     sizeof(in_place) - length);
    }
}

int main(void)
{
    test_counter_encoding();
    test_crypt_lengths_and_in_place();
    return 0;
}
