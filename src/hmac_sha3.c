#include "hmac_sha3.h"

#include "util.h"

#include <string.h>

#define HMAC_IPAD 0x36U
#define HMAC_OPAD 0x5cU

static const uint8_t animagus_core_label[] = "Animagus-AES-v1/CORE";
static const uint8_t animagus_tweak_label[] = "Animagus-AES-v1/TWEAK";

_Static_assert(sizeof(size_t) <= sizeof(uint64_t),
               "Animagus v1 length encoding requires size_t to fit uint64_t");

static void encode_u64_be(uint8_t out[8], size_t value)
{
    uint64_t encoded = (uint64_t)value;
    size_t index;

    for (index = 0; index < 8U; ++index) {
        out[7U - index] = (uint8_t)encoded;
        encoded >>= 8U;
    }
}

int hmac_sha3_256_init(struct hmac_sha3_256_ctx *ctx,
                       const uint8_t *key, size_t key_len)
{
    uint8_t key_block[SHA3_256_RATE_BYTES] = { 0 };
    uint8_t pad[SHA3_256_RATE_BYTES];
    uint8_t hashed_key[SHA3_256_DIGEST_SIZE] = { 0 };
    struct sha3_256_ctx key_hash;
    const uint8_t *effective_key = key;
    size_t effective_key_len = key_len;
    size_t index;

    if (ctx == NULL || (key == NULL && key_len != 0U)) {
        return -1;
    }

    if (key_len > SHA3_256_RATE_BYTES) {
        sha3_256_init(&key_hash);
        sha3_256_update_bytes(&key_hash, key, key_len);
        sha3_256_final(&key_hash, hashed_key);
        effective_key = hashed_key;
        effective_key_len = sizeof(hashed_key);
        animagus_secure_zero(&key_hash, sizeof(key_hash));
    }
    if (effective_key_len != 0U) {
        (void)memcpy(key_block, effective_key, effective_key_len);
    }

    for (index = 0; index < sizeof(pad); ++index) {
        pad[index] = key_block[index] ^ HMAC_IPAD;
    }
    sha3_256_init(&ctx->inner_base);
    sha3_256_update_bytes(&ctx->inner_base, pad, sizeof(pad));

    for (index = 0; index < sizeof(pad); ++index) {
        pad[index] = key_block[index] ^ HMAC_OPAD;
    }
    sha3_256_init(&ctx->outer_base);
    sha3_256_update_bytes(&ctx->outer_base, pad, sizeof(pad));

    animagus_secure_zero(hashed_key, sizeof(hashed_key));
    animagus_secure_zero(pad, sizeof(pad));
    animagus_secure_zero(key_block, sizeof(key_block));
    return 0;
}

static void hmac_sha3_256_finish(const struct hmac_sha3_256_ctx *ctx,
                                 struct sha3_256_ctx *inner,
                                 uint8_t out[SHA3_256_DIGEST_SIZE])
{
    struct sha3_256_ctx outer = ctx->outer_base;
    uint8_t inner_digest[SHA3_256_DIGEST_SIZE];

    sha3_256_final(inner, inner_digest);
    sha3_256_update_bytes(&outer, inner_digest, sizeof(inner_digest));
    sha3_256_final(&outer, out);

    animagus_secure_zero(inner_digest, sizeof(inner_digest));
    animagus_secure_zero(&outer, sizeof(outer));
    animagus_secure_zero(inner, sizeof(*inner));
}

void hmac_sha3_256_bytes(const struct hmac_sha3_256_ctx *ctx,
                         const uint8_t *message, size_t message_len,
                         uint8_t out[SHA3_256_DIGEST_SIZE])
{
    struct sha3_256_ctx inner = ctx->inner_base;

    sha3_256_update_bytes(&inner, message, message_len);
    hmac_sha3_256_finish(ctx, &inner, out);
}

void hmac_sha3_256_bytes2(const struct hmac_sha3_256_ctx *ctx,
                          const uint8_t *first, size_t first_len,
                          const uint8_t *second, size_t second_len,
                          uint8_t out[SHA3_256_DIGEST_SIZE])
{
    struct sha3_256_ctx inner = ctx->inner_base;

    sha3_256_update_bytes(&inner, first, first_len);
    sha3_256_update_bytes(&inner, second, second_len);
    hmac_sha3_256_finish(ctx, &inner, out);
}

void hmac_sha3_256_animagus_v1(const struct hmac_sha3_256_ctx *ctx,
                               const uint8_t *tail, size_t tail_len,
                               enum animagus_hash_domain domain,
                               const uint8_t *tweak, size_t tweak_len,
                               uint8_t out[SHA3_256_DIGEST_SIZE])
{
    uint8_t encoded_length[8];
    const uint8_t domain_byte = (uint8_t)domain;
    struct sha3_256_ctx inner = ctx->inner_base;

    sha3_256_update_bytes(&inner, animagus_core_label,
                          sizeof(animagus_core_label) - 1U);
    sha3_256_update_bytes(&inner, &domain_byte, sizeof(domain_byte));
    encode_u64_be(encoded_length, tail_len);
    sha3_256_update_bytes(&inner, encoded_length, sizeof(encoded_length));
    encode_u64_be(encoded_length, tweak_len);
    sha3_256_update_bytes(&inner, encoded_length, sizeof(encoded_length));
    sha3_256_update_bytes(&inner, tail, tail_len);
    sha3_256_update_bytes(&inner, tweak, tweak_len);
    hmac_sha3_256_finish(ctx, &inner, out);
}

void hmac_sha3_256_tweak_v1(const struct hmac_sha3_256_ctx *ctx,
                            const uint8_t *nonce, size_t nonce_len,
                            const uint8_t *ad, size_t ad_len,
                            uint8_t out[SHA3_256_DIGEST_SIZE])
{
    uint8_t encoded_length[8];
    struct sha3_256_ctx inner = ctx->inner_base;

    sha3_256_update_bytes(&inner, animagus_tweak_label,
                          sizeof(animagus_tweak_label) - 1U);
    encode_u64_be(encoded_length, nonce_len);
    sha3_256_update_bytes(&inner, encoded_length, sizeof(encoded_length));
    encode_u64_be(encoded_length, ad_len);
    sha3_256_update_bytes(&inner, encoded_length, sizeof(encoded_length));
    sha3_256_update_bytes(&inner, nonce, nonce_len);
    sha3_256_update_bytes(&inner, ad, ad_len);
    hmac_sha3_256_finish(ctx, &inner, out);
}
