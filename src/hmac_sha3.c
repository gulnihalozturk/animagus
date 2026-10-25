#include "hmac_sha3.h"

#include "util.h"

#include <string.h>

#define HMAC_IPAD 0x36U
#define HMAC_OPAD 0x5cU

static const uint8_t animagus_kdf_label_prefix[] = "animagus/";
static const char *const animagus_kdf_roles[] = {
    "head1", "head2", "seed", "ctr", "hash",
};

_Static_assert(sizeof(size_t) <= sizeof(uint64_t),
               "Animagus length encoding requires size_t to fit uint64_t");

static void encode_u32_be(uint8_t out[4], uint32_t value)
{
    out[0] = (uint8_t)(value >> 24U);
    out[1] = (uint8_t)(value >> 16U);
    out[2] = (uint8_t)(value >> 8U);
    out[3] = (uint8_t)value;
}

static void encode_u64_be(uint8_t out[8], uint64_t value)
{
    size_t index;

    for (index = 0; index < 8U; ++index) {
        out[7U - index] = (uint8_t)value;
        value >>= 8U;
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

int hmac_sha3_256_kdf_v2(const struct hmac_sha3_256_ctx *root,
                         const char *role, size_t key_len,
                         uint8_t out[SHA3_256_DIGEST_SIZE])
{
    /* BE32(1) || "animagus/" || role || 0x00 || BE32(L); roles are short. */
    uint8_t fixed_input[4U + sizeof(animagus_kdf_label_prefix) - 1U +
                        8U + 1U + 4U];
    size_t role_len = 0;
    size_t index;
    size_t offset = 0;
    int known = 0;

    for (index = 0;
         index < sizeof(animagus_kdf_roles) / sizeof(animagus_kdf_roles[0]);
         ++index) {
        if (role != NULL && strcmp(role, animagus_kdf_roles[index]) == 0) {
            known = 1;
            role_len = strlen(role);
        }
    }
    if (!known || key_len > 32U) {
        return -1;
    }

    encode_u32_be(fixed_input + offset, 1U);
    offset += 4U;
    memcpy(fixed_input + offset, animagus_kdf_label_prefix,
           sizeof(animagus_kdf_label_prefix) - 1U);
    offset += sizeof(animagus_kdf_label_prefix) - 1U;
    memcpy(fixed_input + offset, role, role_len);
    offset += role_len;
    fixed_input[offset++] = 0x00U;
    encode_u32_be(fixed_input + offset, (uint32_t)(8U * key_len));
    offset += 4U;

    hmac_sha3_256_bytes(root, fixed_input, offset, out);
    return 0;
}

void hmac_sha3_256_core_v2(const struct hmac_sha3_256_ctx *ctx,
                           const uint8_t *tail, size_t tail_len,
                           enum animagus_hash_role role,
                           const uint8_t tweak[ANIMAGUS_HASH_TWEAK_BYTES],
                           uint8_t out[SHA3_256_DIGEST_SIZE])
{
    const uint8_t role_bits = (uint8_t)role;
    struct sha3_256_ctx inner = ctx->inner_base;

    sha3_256_update_bytes(&inner, tail, tail_len);
    sha3_256_update_bits(&inner, &role_bits, 2U);
    /* The sponge is now two bits past a byte boundary, so the tweak takes
     * the bit-granular absorption path. */
    sha3_256_update_bytes(&inner, tweak, ANIMAGUS_HASH_TWEAK_BYTES);
    hmac_sha3_256_finish(ctx, &inner, out);
}

int hmac_sha3_256_tweak_v2(const struct hmac_sha3_256_ctx *ctx,
                           uint8_t application,
                           const uint8_t *nonce, size_t nonce_len,
                           const uint8_t *ad, size_t ad_len,
                           uint8_t out[SHA3_256_DIGEST_SIZE])
{
    static const uint8_t zero_block[ANIMAGUS_HASH_TWEAK_BYTES] = { 0 };
    const uint8_t role_bits = (uint8_t)ANIMAGUS_ROLE_TWEAK;
    uint8_t header[9];
    struct sha3_256_ctx inner;

    if (animagus_size_exceeds(nonce_len, ANIMAGUS_HASH_MAX_FRAMED_BYTES) ||
        animagus_size_exceeds(ad_len, ANIMAGUS_HASH_MAX_FRAMED_BYTES)) {
        return -1;
    }

    inner = ctx->inner_base;
    header[0] = application;
    encode_u64_be(header + 1, (uint64_t)nonce_len * 8U);
    sha3_256_update_bytes(&inner, header, sizeof(header));
    sha3_256_update_bytes(&inner, nonce, nonce_len);
    sha3_256_update_bytes(&inner, ad, ad_len);
    sha3_256_update_bits(&inner, &role_bits, 2U);
    sha3_256_update_bytes(&inner, zero_block, sizeof(zero_block));
    hmac_sha3_256_finish(ctx, &inner, out);
    return 0;
}
