#include "animagus_ctr.h"

#include "util.h"

#include <string.h>

void animagus_ctr_counter(uint8_t out[16], const uint8_t seed[16],
                          uint64_t index)
{
    size_t byte_index;

    memcpy(out, seed, 16U);
    for (byte_index = 0; byte_index < 8U; ++byte_index) {
        out[15U - byte_index] ^= (uint8_t)(index >> (8U * byte_index));
    }
}

void animagus_ctr_crypt(const struct animagus_aes_ctx *ctx, uint8_t *out,
                        const uint8_t *in, size_t length,
                        const uint8_t seed[16])
{
    uint8_t counters[8][16];
    uint8_t keystream[8][16];
    uint64_t block_index = 0;
    size_t offset = 0;

    while (offset < length) {
        size_t remaining = length - offset;
        size_t block_count = remaining / 16U;
        size_t batch_length;
        size_t counter_index;
        size_t byte_index;

        if ((remaining % 16U) != 0U) {
            ++block_count;
        }
        if (block_count > 8U) {
            block_count = 8U;
        }
        for (counter_index = 0; counter_index < block_count; ++counter_index) {
            animagus_ctr_counter(counters[counter_index], seed,
                                 block_index + (uint64_t)counter_index);
        }
        animagus_aes_encrypt_blocks(ctx, &keystream[0][0], &counters[0][0],
                                    block_count);

        batch_length = remaining < 16U * block_count ? remaining :
                       16U * block_count;
        for (byte_index = 0; byte_index < batch_length; ++byte_index) {
            out[offset + byte_index] = in[offset + byte_index] ^
                                       keystream[byte_index / 16U]
                                                [byte_index % 16U];
        }
        offset += batch_length;
        block_index += (uint64_t)block_count;
    }

    animagus_secure_zero(counters, sizeof(counters));
    animagus_secure_zero(keystream, sizeof(keystream));
}
