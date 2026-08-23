#pragma once

#include <stddef.h>
#include <stdint.h>

#define SHA3_256_RATE_BITS 1088U
#define SHA3_256_RATE_BYTES 136U
#define SHA3_256_DIGEST_SIZE 32U

struct sha3_256_ctx {
    uint64_t lanes[25];
    size_t bit_pos;
};

void sha3_256_init(struct sha3_256_ctx *ctx);
void sha3_256_update_bytes(struct sha3_256_ctx *ctx, const uint8_t *data,
                           size_t length);
void sha3_256_update_bits(struct sha3_256_ctx *ctx, const uint8_t *data,
                          size_t bit_len);
void sha3_256_final(const struct sha3_256_ctx *ctx,
                    uint8_t out[SHA3_256_DIGEST_SIZE]);
