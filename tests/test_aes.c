#include "aes.h"
#include "test_common.h"

#include <stdint.h>
#include <string.h>

static void check_vector(const char *key_hex, const char *plaintext_hex,
                         const char *ciphertext_hex)
{
    uint8_t key[32], plaintext[16], expected[16], actual[16], recovered[16];
    struct animagus_aes_ctx ctx;
    size_t key_len = hex_decode(key, sizeof(key), key_hex);

    ASSERT_EQ(hex_decode(plaintext, sizeof(plaintext), plaintext_hex), 16);
    ASSERT_EQ(hex_decode(expected, sizeof(expected), ciphertext_hex), 16);
    ASSERT_EQ(animagus_aes_setkey(&ctx, key, key_len,
                                  ANIMAGUS_AES_PORTABLE), 0);
    animagus_aes_encrypt_block(&ctx, actual, plaintext);
    ASSERT_MEMEQ(actual, expected, 16);
    animagus_aes_decrypt_block(&ctx, recovered, actual);
    ASSERT_MEMEQ(recovered, plaintext, 16);
}

static void check_rejected_keys(void)
{
    const size_t invalid_lengths[] = { 0, 15, 17, 23, 25, 33 };
    uint8_t key[33] = { 0 };
    struct animagus_aes_ctx ctx;
    size_t index;

    for (index = 0; index < sizeof(invalid_lengths) / sizeof(invalid_lengths[0]);
         ++index) {
        ASSERT_EQ(animagus_aes_setkey(&ctx, key, invalid_lengths[index],
                                      ANIMAGUS_AES_PORTABLE), -1);
    }
}

static void fill_pattern(uint8_t *bytes, size_t length, uint8_t seed)
{
    size_t index;

    for (index = 0; index < length; ++index) {
        bytes[index] = (uint8_t)(seed + index * 29U);
    }
}

static void check_hardware_backend(void)
{
    const size_t key_lengths[] = { 16U, 24U, 32U };
    const size_t block_counts[] = { 1U, 2U, 5U, 8U, 9U, 17U };
    uint8_t key[32] = { 0 }, input[17U * 16U];
    uint8_t portable_output[sizeof(input)], hardware_output[sizeof(input)];
    uint8_t portable_recovered[16], hardware_recovered[16];
    struct animagus_aes_ctx portable, hardware;
    size_t key_index, count_index;

    if (!host_has_aes_instructions()) {
        ASSERT_EQ(animagus_aes_hardware_available(), false);
        ASSERT_EQ(animagus_aes_setkey(&hardware, key, 16U,
                                      ANIMAGUS_AES_HARDWARE), -1);
        return;
    }

    ASSERT_EQ(animagus_aes_hardware_available(), true);
    fill_pattern(input, sizeof(input), 0x61U);
    for (key_index = 0;
         key_index < sizeof(key_lengths) / sizeof(key_lengths[0]);
         ++key_index) {
        fill_pattern(key, key_lengths[key_index], (uint8_t)(0x21U + key_index));
        ASSERT_EQ(animagus_aes_setkey(&portable, key, key_lengths[key_index],
                                      ANIMAGUS_AES_PORTABLE), 0);
        ASSERT_EQ(animagus_aes_setkey(&hardware, key, key_lengths[key_index],
                                      ANIMAGUS_AES_HARDWARE), 0);

        animagus_aes_encrypt_block(&portable, portable_output, input);
        animagus_aes_encrypt_block(&hardware, hardware_output, input);
        ASSERT_MEMEQ(hardware_output, portable_output, 16U);
        animagus_aes_decrypt_block(&portable, portable_recovered,
                                   portable_output);
        animagus_aes_decrypt_block(&hardware, hardware_recovered,
                                   hardware_output);
        ASSERT_MEMEQ(portable_recovered, input, 16U);
        ASSERT_MEMEQ(hardware_recovered, input, 16U);

        for (count_index = 0;
             count_index < sizeof(block_counts) / sizeof(block_counts[0]);
             ++count_index) {
            size_t byte_count = block_counts[count_index] * 16U;

            animagus_aes_encrypt_blocks(&portable, portable_output, input,
                                        block_counts[count_index]);
            animagus_aes_encrypt_blocks(&hardware, hardware_output, input,
                                        block_counts[count_index]);
            ASSERT_MEMEQ(hardware_output, portable_output, byte_count);
        }
    }
}

static void check_encrypt_blocks(void)
{
    const uint8_t key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    const uint8_t input[32] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    };
    const uint8_t canary_expected[16] = {
        0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
        0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
    };
    uint8_t expected[32], actual[32], in_place[32], canary[16];
    struct animagus_aes_ctx ctx;

    ASSERT_EQ(animagus_aes_setkey(&ctx, key, sizeof(key),
                                  ANIMAGUS_AES_PORTABLE), 0);
    animagus_aes_encrypt_block(&ctx, expected, input);
    animagus_aes_encrypt_block(&ctx, expected + 16, input + 16);

    animagus_aes_encrypt_blocks(&ctx, actual, input, 2);
    ASSERT_MEMEQ(actual, expected, sizeof(expected));

    memcpy(in_place, input, sizeof(in_place));
    animagus_aes_encrypt_blocks(&ctx, in_place, in_place, 2);
    ASSERT_MEMEQ(in_place, expected, sizeof(in_place));

    memcpy(canary, canary_expected, sizeof(canary));
    animagus_aes_encrypt_blocks(&ctx, canary, input, 0);
    ASSERT_MEMEQ(canary, canary_expected, sizeof(canary));
}

int main(void)
{
    const char *pt = "00112233445566778899aabbccddeeff";
    check_vector("000102030405060708090a0b0c0d0e0f", pt,
                 "69c4e0d86a7b0430d8cdb78070b4c55a");
    check_vector("000102030405060708090a0b0c0d0e0f"
                 "1011121314151617", pt,
                 "dda97ca4864cdfe06eaf70a0ec0d7191");
    check_vector("000102030405060708090a0b0c0d0e0f"
                 "101112131415161718191a1b1c1d1e1f", pt,
                 "8ea2b7ca516745bfeafc49904b496089");
    check_rejected_keys();
    check_encrypt_blocks();
    check_hardware_backend();
    return 0;
}
