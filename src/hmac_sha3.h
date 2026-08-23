#pragma once

#include "sha3.h"

#include <stddef.h>
#include <stdint.h>

enum animagus_hash_domain {
    ANIMAGUS_HASH_PLAINTEXT = 0x01,
    ANIMAGUS_HASH_CIPHERTEXT = 0x02,
};

struct hmac_sha3_256_ctx {
    struct sha3_256_ctx inner_base;
    struct sha3_256_ctx outer_base;
};

int hmac_sha3_256_init(struct hmac_sha3_256_ctx *ctx,
                       const uint8_t *key, size_t key_len);
void hmac_sha3_256_bytes(const struct hmac_sha3_256_ctx *ctx,
                         const uint8_t *message, size_t message_len,
                         uint8_t out[SHA3_256_DIGEST_SIZE]);
void hmac_sha3_256_bytes2(const struct hmac_sha3_256_ctx *ctx,
                          const uint8_t *first, size_t first_len,
                          const uint8_t *second, size_t second_len,
                          uint8_t out[SHA3_256_DIGEST_SIZE]);
void hmac_sha3_256_animagus_v1(const struct hmac_sha3_256_ctx *ctx,
                               const uint8_t *tail, size_t tail_len,
                               enum animagus_hash_domain domain,
                               const uint8_t *tweak, size_t tweak_len,
                               uint8_t out[SHA3_256_DIGEST_SIZE]);
void hmac_sha3_256_tweak_v1(const struct hmac_sha3_256_ctx *ctx,
                            const uint8_t *nonce, size_t nonce_len,
                            const uint8_t *ad, size_t ad_len,
                            uint8_t out[SHA3_256_DIGEST_SIZE]);
