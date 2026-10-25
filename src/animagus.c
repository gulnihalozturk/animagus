#include "animagus.h"

#include "aes.h"
#include "animagus_ctr.h"
#include "animagus_internal.h"
#include "hmac_sha3.h"
#include "util.h"

#include <stddef.h>
#include <string.h>

/* "ANIMAGV2": distinguishes v2 contexts from the retired v1 layout. */
#define ANIMAGUS_CTX_MAGIC UINT64_C(0x414e494d41475632)

enum animagus_working_key {
    ANIMAGUS_KEY_HEAD1 = 0,
    ANIMAGUS_KEY_HEAD2 = 1,
    ANIMAGUS_KEY_SEED = 2,
    ANIMAGUS_KEY_CTR = 3,
    ANIMAGUS_KEY_HASH = 4,
    ANIMAGUS_KEY_COUNT = 5,
};

static const char *const animagus_key_roles[ANIMAGUS_KEY_COUNT] = {
    "head1", "head2", "seed", "ctr", "hash",
};

struct animagus_ctx_impl {
    struct animagus_aes_ctx head1;
    struct animagus_aes_ctx head2;
    struct animagus_aes_ctx seed;
    struct animagus_aes_ctx ctr;
    struct hmac_sha3_256_ctx hash;
    uint64_t magic;
};

_Static_assert(sizeof(struct animagus_ctx_impl) <= ANIMAGUS_CONTEXT_BYTES,
               "Animagus implementation must fit in the public context");
_Static_assert(_Alignof(struct animagus_ctx_impl) <= _Alignof(animagus_ctx),
               "Animagus implementation alignment exceeds public context");
_Static_assert(ANIMAGUS_TWEAK_SIZE == ANIMAGUS_HASH_TWEAK_BYTES,
               "Core hash frame and public tweak size must agree");
_Static_assert(ANIMAGUS_MAX_FRAMED_SIZE == ANIMAGUS_HASH_MAX_FRAMED_BYTES,
               "Public and internal framed-length limits must agree");
_Static_assert(ANIMAGUS_MIN_MESSAGE_SIZE == 2U * ANIMAGUS_BLOCK_SIZE,
               "The core input is two head blocks plus a tail");

int animagus_ctx_state(const animagus_ctx *ctx)
{
    uint64_t magic;

    if (ctx == NULL) {
        return ANIMAGUS_ERR_ARGUMENT;
    }
    memcpy(&magic, ctx->opaque + offsetof(struct animagus_ctx_impl, magic),
           sizeof(magic));
    return magic == ANIMAGUS_CTX_MAGIC ? ANIMAGUS_OK : ANIMAGUS_ERR_STATE;
}

static int animagus_load_impl(struct animagus_ctx_impl *impl,
                              const animagus_ctx *ctx)
{
    int result = animagus_ctx_state(ctx);

    if (result != ANIMAGUS_OK) {
        return result;
    }
    memcpy(impl, ctx->opaque, sizeof(*impl));
    return ANIMAGUS_OK;
}

static int animagus_check_length(size_t len)
{
    if (len < ANIMAGUS_MIN_MESSAGE_SIZE ||
        animagus_size_exceeds(len, ANIMAGUS_MAX_MESSAGE_SIZE)) {
        return ANIMAGUS_ERR_MESSAGE_SIZE;
    }
    return ANIMAGUS_OK;
}

static void animagus_xor_block(uint8_t out[16], const uint8_t left[16],
                               const uint8_t right[16])
{
    size_t index;

    for (index = 0; index < 16U; ++index) {
        out[index] = left[index] ^ right[index];
    }
}

static int animagus_validate_common(const animagus_ctx *ctx, uint8_t *dst,
                                    const uint8_t *src, size_t len,
                                    const uint8_t *tweak)
{
    int result = animagus_ctx_state(ctx);

    if (result != ANIMAGUS_OK) {
        return result;
    }
    if (dst == NULL || src == NULL || tweak == NULL) {
        return ANIMAGUS_ERR_ARGUMENT;
    }
    result = animagus_check_length(len);
    if (result != ANIMAGUS_OK) {
        return result;
    }
    if ((dst != src && animagus_ranges_overlap(dst, len, src, len)) ||
        animagus_ranges_overlap(dst, len, tweak, ANIMAGUS_TWEAK_SIZE)) {
        return ANIMAGUS_ERR_OVERLAP;
    }
    return ANIMAGUS_OK;
}

int animagus_init(animagus_ctx *ctx, const uint8_t *key, size_t key_len)
{
    return animagus_init_ex(ctx, key, key_len, ANIMAGUS_BACKEND_AUTO);
}

int animagus_init_ex(animagus_ctx *ctx, const uint8_t *key, size_t key_len,
                     enum animagus_backend backend)
{
    struct animagus_ctx_impl temporary = { 0 };
    struct hmac_sha3_256_ctx root_hmac = { 0 };
    uint8_t working[ANIMAGUS_KEY_COUNT][SHA3_256_DIGEST_SIZE] = { { 0 } };
    enum animagus_aes_backend aes_backend;
    size_t index;
    int result = ANIMAGUS_OK;

    if (ctx == NULL || key == NULL) {
        return ANIMAGUS_ERR_ARGUMENT;
    }
    if (key_len != 16U && key_len != 24U && key_len != 32U) {
        return ANIMAGUS_ERR_KEY_SIZE;
    }

    if (backend == ANIMAGUS_BACKEND_AUTO) {
        backend = animagus_aes_hardware_available() ?
            ANIMAGUS_BACKEND_HARDWARE : ANIMAGUS_BACKEND_PORTABLE;
    }
    if (backend == ANIMAGUS_BACKEND_PORTABLE) {
        aes_backend = ANIMAGUS_AES_PORTABLE;
    } else if (backend == ANIMAGUS_BACKEND_HARDWARE) {
        if (!animagus_aes_hardware_available()) {
            result = ANIMAGUS_ERR_BACKEND;
            goto cleanup;
        }
        aes_backend = ANIMAGUS_AES_HARDWARE;
    } else {
        result = ANIMAGUS_ERR_ARGUMENT;
        goto cleanup;
    }

    if (hmac_sha3_256_init(&root_hmac, key, key_len) != 0) {
        result = ANIMAGUS_ERR_BACKEND;
        goto cleanup;
    }
    for (index = 0; index < ANIMAGUS_KEY_COUNT; ++index) {
        if (hmac_sha3_256_kdf_v2(&root_hmac, animagus_key_roles[index],
                                 key_len, working[index]) != 0) {
            result = ANIMAGUS_ERR_BACKEND;
            goto cleanup;
        }
    }

    if (animagus_aes_setkey(&temporary.head1, working[ANIMAGUS_KEY_HEAD1],
                            key_len, aes_backend) != 0 ||
        animagus_aes_setkey(&temporary.head2, working[ANIMAGUS_KEY_HEAD2],
                            key_len, aes_backend) != 0 ||
        animagus_aes_setkey(&temporary.seed, working[ANIMAGUS_KEY_SEED],
                            key_len, aes_backend) != 0 ||
        animagus_aes_setkey(&temporary.ctr, working[ANIMAGUS_KEY_CTR],
                            key_len, aes_backend) != 0 ||
        hmac_sha3_256_init(&temporary.hash, working[ANIMAGUS_KEY_HASH],
                           key_len) != 0) {
        result = ANIMAGUS_ERR_BACKEND;
        goto cleanup;
    }
    temporary.magic = ANIMAGUS_CTX_MAGIC;
    memset(ctx->opaque, 0, sizeof(ctx->opaque));
    memcpy(ctx->opaque, &temporary, sizeof(temporary));

cleanup:
    animagus_secure_zero(working, sizeof(working));
    animagus_secure_zero(&root_hmac, sizeof(root_hmac));
    animagus_secure_zero(&temporary, sizeof(temporary));
    return result;
}

int animagus_core_encrypt(const animagus_ctx *ctx, uint8_t *dst,
                          const uint8_t head[ANIMAGUS_BLOCK_SIZE],
                          const uint8_t *rest, size_t len,
                          const uint8_t tweak[ANIMAGUS_TWEAK_SIZE])
{
    struct animagus_ctx_impl impl = { 0 };
    uint8_t x[SHA3_256_DIGEST_SIZE];
    uint8_t f[16], b[16], j[16], f_star[16], b_star[16];
    uint8_t first[16], second[16], tmp[16];
    int result;

    result = animagus_load_impl(&impl, ctx);
    if (result != ANIMAGUS_OK) {
        goto cleanup;
    }
    result = animagus_check_length(len);
    if (result != ANIMAGUS_OK) {
        goto cleanup;
    }

    memcpy(first, head, sizeof(first));
    memcpy(second, rest, sizeof(second));

    /* X1 = H(P_tail || 10 || T); A1 = MSB(X1), A2 = LSB(X1). */
    hmac_sha3_256_core_v2(&impl.hash, rest + 16U, len - 32U,
                          ANIMAGUS_ROLE_PLAINTEXT_TAIL, tweak, x);

    /* F = E_head1(P1 ^ A2), B = E_head2(P2 ^ A1). */
    animagus_xor_block(tmp, first, x + 16U);
    animagus_aes_encrypt_block(&impl.head1, f, tmp);
    animagus_xor_block(tmp, second, x);
    animagus_aes_encrypt_block(&impl.head2, b, tmp);

    /* J = E_seed(F ^ B); F* = F ^ J, B* = B ^ J. */
    animagus_xor_block(tmp, f, b);
    animagus_aes_encrypt_block(&impl.seed, j, tmp);
    animagus_xor_block(f_star, f, j);
    animagus_xor_block(b_star, b, j);

    animagus_ctr_crypt(&impl.ctr, dst + 32U, rest + 16U, len - 32U, j);

    /* X2 = H(C_tail || 01 || T); A3 = MSB(X2), A4 = LSB(X2). */
    hmac_sha3_256_core_v2(&impl.hash, dst + 32U, len - 32U,
                          ANIMAGUS_ROLE_CIPHERTEXT_TAIL, tweak, x);

    /* C1 = E_head1(F*) ^ A4, C2 = E_head2(B*) ^ A3. */
    animagus_aes_encrypt_block(&impl.head1, tmp, f_star);
    animagus_xor_block(first, tmp, x + 16U);
    animagus_aes_encrypt_block(&impl.head2, tmp, b_star);
    animagus_xor_block(second, tmp, x);

    memcpy(dst, first, sizeof(first));
    memcpy(dst + sizeof(first), second, sizeof(second));

cleanup:
    animagus_secure_zero(tmp, sizeof(tmp));
    animagus_secure_zero(second, sizeof(second));
    animagus_secure_zero(first, sizeof(first));
    animagus_secure_zero(b_star, sizeof(b_star));
    animagus_secure_zero(f_star, sizeof(f_star));
    animagus_secure_zero(j, sizeof(j));
    animagus_secure_zero(b, sizeof(b));
    animagus_secure_zero(f, sizeof(f));
    animagus_secure_zero(x, sizeof(x));
    animagus_secure_zero(&impl, sizeof(impl));
    return result;
}

int animagus_core_decrypt(const animagus_ctx *ctx,
                          uint8_t head_out[ANIMAGUS_BLOCK_SIZE],
                          uint8_t *rest_out, const uint8_t *src, size_t len,
                          const uint8_t tweak[ANIMAGUS_TWEAK_SIZE])
{
    struct animagus_ctx_impl impl = { 0 };
    uint8_t x[SHA3_256_DIGEST_SIZE];
    uint8_t f[16], b[16], j[16], f_star[16], b_star[16];
    uint8_t first[16], second[16], tmp[16];
    int result;

    result = animagus_load_impl(&impl, ctx);
    if (result != ANIMAGUS_OK) {
        goto cleanup;
    }
    result = animagus_check_length(len);
    if (result != ANIMAGUS_OK) {
        goto cleanup;
    }

    memcpy(first, src, sizeof(first));
    memcpy(second, src + sizeof(first), sizeof(second));

    /* X2 = H(C_tail || 01 || T); A3 = MSB(X2), A4 = LSB(X2). */
    hmac_sha3_256_core_v2(&impl.hash, src + 32U, len - 32U,
                          ANIMAGUS_ROLE_CIPHERTEXT_TAIL, tweak, x);

    /* F* = D_head1(C1 ^ A4), B* = D_head2(C2 ^ A3). */
    animagus_xor_block(tmp, first, x + 16U);
    animagus_aes_decrypt_block(&impl.head1, f_star, tmp);
    animagus_xor_block(tmp, second, x);
    animagus_aes_decrypt_block(&impl.head2, b_star, tmp);

    /* J = E_seed(F* ^ B*) = E_seed(F ^ B); F = F* ^ J, B = B* ^ J. */
    animagus_xor_block(tmp, f_star, b_star);
    animagus_aes_encrypt_block(&impl.seed, j, tmp);
    animagus_xor_block(f, f_star, j);
    animagus_xor_block(b, b_star, j);

    animagus_ctr_crypt(&impl.ctr, rest_out + 16U, src + 32U, len - 32U, j);

    /* X1 = H(P_tail || 10 || T); A1 = MSB(X1), A2 = LSB(X1). */
    hmac_sha3_256_core_v2(&impl.hash, rest_out + 16U, len - 32U,
                          ANIMAGUS_ROLE_PLAINTEXT_TAIL, tweak, x);

    /* P1 = D_head1(F) ^ A2, P2 = D_head2(B) ^ A1. */
    animagus_aes_decrypt_block(&impl.head1, tmp, f);
    animagus_xor_block(first, tmp, x + 16U);
    animagus_aes_decrypt_block(&impl.head2, tmp, b);
    animagus_xor_block(second, tmp, x);

    memcpy(rest_out, second, sizeof(second));
    memcpy(head_out, first, sizeof(first));

cleanup:
    animagus_secure_zero(tmp, sizeof(tmp));
    animagus_secure_zero(second, sizeof(second));
    animagus_secure_zero(first, sizeof(first));
    animagus_secure_zero(b_star, sizeof(b_star));
    animagus_secure_zero(f_star, sizeof(f_star));
    animagus_secure_zero(j, sizeof(j));
    animagus_secure_zero(b, sizeof(b));
    animagus_secure_zero(f, sizeof(f));
    animagus_secure_zero(x, sizeof(x));
    animagus_secure_zero(&impl, sizeof(impl));
    return result;
}

int animagus_encrypt(const animagus_ctx *ctx, uint8_t *dst,
                     const uint8_t *src, size_t len,
                     const uint8_t tweak[ANIMAGUS_TWEAK_SIZE])
{
    int result = animagus_validate_common(ctx, dst, src, len, tweak);

    if (result != ANIMAGUS_OK) {
        return result;
    }
    return animagus_core_encrypt(ctx, dst, src, src + ANIMAGUS_BLOCK_SIZE,
                                 len, tweak);
}

int animagus_decrypt(const animagus_ctx *ctx, uint8_t *dst,
                     const uint8_t *src, size_t len,
                     const uint8_t tweak[ANIMAGUS_TWEAK_SIZE])
{
    int result = animagus_validate_common(ctx, dst, src, len, tweak);

    if (result != ANIMAGUS_OK) {
        return result;
    }
    return animagus_core_decrypt(ctx, dst, dst + ANIMAGUS_BLOCK_SIZE, src,
                                 len, tweak);
}

static int animagus_validate_tweak_inputs(enum animagus_application app,
                                          const uint8_t *nonce,
                                          size_t nonce_len,
                                          const uint8_t *ad, size_t ad_len)
{
    if ((nonce == NULL && nonce_len != 0U) || (ad == NULL && ad_len != 0U)) {
        return ANIMAGUS_ERR_ARGUMENT;
    }
    if (animagus_size_exceeds(nonce_len, ANIMAGUS_MAX_FRAMED_SIZE) ||
        animagus_size_exceeds(ad_len, ANIMAGUS_MAX_FRAMED_SIZE)) {
        return ANIMAGUS_ERR_ARGUMENT;
    }
    switch (app) {
    case ANIMAGUS_APPLICATION_AEAD:
        return nonce_len == 0U ? ANIMAGUS_ERR_ARGUMENT : ANIMAGUS_OK;
    case ANIMAGUS_APPLICATION_TWEAKABLE:
        return nonce_len != 0U ? ANIMAGUS_ERR_ARGUMENT : ANIMAGUS_OK;
    case ANIMAGUS_APPLICATION_DAE:
        return (nonce_len != 0U || ad_len != 0U) ?
            ANIMAGUS_ERR_ARGUMENT : ANIMAGUS_OK;
    default:
        return ANIMAGUS_ERR_ARGUMENT;
    }
}

int animagus_make_tweak(const animagus_ctx *ctx,
                        uint8_t tweak[ANIMAGUS_TWEAK_SIZE],
                        enum animagus_application application,
                        const uint8_t *nonce, size_t nonce_len,
                        const uint8_t *ad, size_t ad_len)
{
    struct animagus_ctx_impl impl = { 0 };
    uint8_t digest[SHA3_256_DIGEST_SIZE];
    int result;

    result = animagus_load_impl(&impl, ctx);
    if (result != ANIMAGUS_OK) {
        goto cleanup;
    }
    if (tweak == NULL) {
        result = ANIMAGUS_ERR_ARGUMENT;
        goto cleanup;
    }
    result = animagus_validate_tweak_inputs(application, nonce, nonce_len,
                                            ad, ad_len);
    if (result != ANIMAGUS_OK) {
        goto cleanup;
    }

    if (hmac_sha3_256_tweak_v2(&impl.hash, (uint8_t)application,
                               nonce, nonce_len, ad, ad_len, digest) != 0) {
        result = ANIMAGUS_ERR_ARGUMENT;
        goto cleanup;
    }
    memcpy(tweak, digest, ANIMAGUS_TWEAK_SIZE);

cleanup:
    animagus_secure_zero(digest, sizeof(digest));
    animagus_secure_zero(&impl, sizeof(impl));
    return result;
}

int animagus_derive_tweak(const animagus_ctx *ctx,
                          uint8_t tweak[ANIMAGUS_TWEAK_SIZE],
                          const uint8_t *context, size_t context_len)
{
    /* The only derived tweak the paper defines for direct core use. The
     * AEAD and DAE tweaks stay inside the derived layer. */
    return animagus_make_tweak(ctx, tweak, ANIMAGUS_APPLICATION_TWEAKABLE,
                               NULL, 0U, context, context_len);
}

void animagus_clear(animagus_ctx *ctx)
{
    if (ctx != NULL) {
        animagus_secure_zero(ctx, sizeof(*ctx));
    }
}
