#include "sha3.h"

#include "util.h"

#include <string.h>

static const uint64_t round_constants[24] = {
    UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082),
    UINT64_C(0x800000000000808a), UINT64_C(0x8000000080008000),
    UINT64_C(0x000000000000808b), UINT64_C(0x0000000080000001),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
    UINT64_C(0x000000000000008a), UINT64_C(0x0000000000000088),
    UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000a),
    UINT64_C(0x000000008000808b), UINT64_C(0x800000000000008b),
    UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
    UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
    UINT64_C(0x000000000000800a), UINT64_C(0x800000008000000a),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080),
    UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008),
};

static const unsigned int rotations[25] = {
     0U,  1U, 62U, 28U, 27U,
    36U, 44U,  6U, 55U, 20U,
     3U, 10U, 43U, 25U, 39U,
    41U, 45U, 15U, 21U,  8U,
    18U,  2U, 61U, 56U, 14U,
};

static uint64_t rotate_left64(uint64_t value, unsigned int shift)
{
    if (shift == 0U) {
        return value;
    }
    return (value << shift) | (value >> (64U - shift));
}

static void keccak_f1600(uint64_t state[25])
{
    size_t round;

    for (round = 0; round < 24U; ++round) {
        uint64_t parity[5], delta[5], moved[25];
        size_t x, y;

        for (x = 0; x < 5U; ++x) {
            parity[x] = state[x] ^ state[x + 5U] ^ state[x + 10U] ^
                        state[x + 15U] ^ state[x + 20U];
        }
        for (x = 0; x < 5U; ++x) {
            delta[x] = parity[(x + 4U) % 5U] ^
                       rotate_left64(parity[(x + 1U) % 5U], 1U);
        }
        for (y = 0; y < 5U; ++y) {
            for (x = 0; x < 5U; ++x) {
                state[x + 5U * y] ^= delta[x];
            }
        }

        for (y = 0; y < 5U; ++y) {
            for (x = 0; x < 5U; ++x) {
                moved[y + 5U * ((2U * x + 3U * y) % 5U)] =
                    rotate_left64(state[x + 5U * y],
                                  rotations[x + 5U * y]);
            }
        }

        for (y = 0; y < 5U; ++y) {
            for (x = 0; x < 5U; ++x) {
                state[x + 5U * y] =
                    moved[x + 5U * y] ^
                    ((~moved[(x + 1U) % 5U + 5U * y]) &
                     moved[(x + 2U) % 5U + 5U * y]);
            }
        }
        state[0] ^= round_constants[round];
    }
}

static void sha3_absorb_bit(struct sha3_256_ctx *ctx, unsigned int bit)
{
    if (bit != 0U) {
        ctx->lanes[ctx->bit_pos / 64U] ^=
            UINT64_C(1) << (ctx->bit_pos % 64U);
    }
    ++ctx->bit_pos;
    if (ctx->bit_pos == SHA3_256_RATE_BITS) {
        keccak_f1600(ctx->lanes);
        ctx->bit_pos = 0;
    }
}

void sha3_256_init(struct sha3_256_ctx *ctx)
{
    (void)memset(ctx, 0, sizeof(*ctx));
}

void sha3_256_update_bytes(struct sha3_256_ctx *ctx, const uint8_t *data,
                           size_t length)
{
    size_t byte_index;

    if ((ctx->bit_pos % 8U) == 0U) {
        for (byte_index = 0; byte_index < length; ++byte_index) {
            ctx->lanes[ctx->bit_pos / 64U] ^=
                (uint64_t)data[byte_index] << (ctx->bit_pos % 64U);
            ctx->bit_pos += 8U;
            if (ctx->bit_pos == SHA3_256_RATE_BITS) {
                keccak_f1600(ctx->lanes);
                ctx->bit_pos = 0;
            }
        }
        return;
    }

    for (byte_index = 0; byte_index < length; ++byte_index) {
        unsigned int bit_index;

        for (bit_index = 0; bit_index < 8U; ++bit_index) {
            sha3_absorb_bit(ctx,
                ((unsigned int)data[byte_index] >> bit_index) & 1U);
        }
    }
}

void sha3_256_update_bits(struct sha3_256_ctx *ctx, const uint8_t *data,
                          size_t bit_len)
{
    size_t bit_index;

    for (bit_index = 0; bit_index < bit_len; ++bit_index) {
        sha3_absorb_bit(ctx,
            ((unsigned int)data[bit_index / 8U] >> (bit_index % 8U)) & 1U);
    }
}

void sha3_256_final(const struct sha3_256_ctx *ctx,
                    uint8_t out[SHA3_256_DIGEST_SIZE])
{
    struct sha3_256_ctx final_ctx = *ctx;
    size_t byte_index;

    sha3_absorb_bit(&final_ctx, 0U);
    sha3_absorb_bit(&final_ctx, 1U);
    sha3_absorb_bit(&final_ctx, 1U);
    final_ctx.lanes[(SHA3_256_RATE_BITS - 1U) / 64U] ^=
        UINT64_C(1) << ((SHA3_256_RATE_BITS - 1U) % 64U);
    keccak_f1600(final_ctx.lanes);

    for (byte_index = 0; byte_index < SHA3_256_DIGEST_SIZE; ++byte_index) {
        out[byte_index] = (uint8_t)
            (final_ctx.lanes[byte_index / 8U] >>
             (8U * (byte_index % 8U)));
    }
    animagus_secure_zero(&final_ctx, sizeof(final_ctx));
}
