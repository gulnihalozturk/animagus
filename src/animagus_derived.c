#include "animagus_derived.h"

#include "animagus_internal.h"
#include "util.h"

#include <stdint.h>
#include <string.h>

/* AUD = 0^128, the fixed authentication block of the paper. */
static const uint8_t animagus_auth_block[ANIMAGUS_AUTH_SIZE] = { 0 };

/* The message is either the in-place part at whole + 16 or disjoint. */
static int animagus_check_part_placement(const uint8_t *whole,
                                         size_t whole_len,
                                         const uint8_t *part,
                                         size_t part_len)
{
    if (part == whole + ANIMAGUS_AUTH_SIZE) {
        return ANIMAGUS_OK;
    }
    return animagus_ranges_overlap(whole, whole_len, part, part_len) ?
        ANIMAGUS_ERR_OVERLAP : ANIMAGUS_OK;
}

static int animagus_validate_auth_encrypt(const animagus_ctx *ctx,
                                          const uint8_t *ciphertext,
                                          const uint8_t *message,
                                          size_t message_len)
{
    int result = animagus_ctx_state(ctx);

    if (result != ANIMAGUS_OK) {
        return result;
    }
    if (ciphertext == NULL || message == NULL) {
        return ANIMAGUS_ERR_ARGUMENT;
    }
    /* The SIZE_MAX guard keeps message_len + 16 from wrapping where size_t
     * is narrower than the profile limit. */
    if (message_len < ANIMAGUS_AUTH_MIN_MESSAGE_SIZE ||
        message_len > SIZE_MAX - ANIMAGUS_AUTH_SIZE ||
        animagus_size_exceeds(message_len, ANIMAGUS_AUTH_MAX_MESSAGE_SIZE)) {
        return ANIMAGUS_ERR_MESSAGE_SIZE;
    }
    return animagus_check_part_placement(ciphertext,
                                         message_len + ANIMAGUS_AUTH_SIZE,
                                         message, message_len);
}

static int animagus_validate_auth_decrypt(const animagus_ctx *ctx,
                                          const uint8_t *message,
                                          const uint8_t *ciphertext,
                                          size_t ciphertext_len)
{
    int result = animagus_ctx_state(ctx);

    if (result != ANIMAGUS_OK) {
        return result;
    }
    if (ciphertext == NULL || message == NULL) {
        return ANIMAGUS_ERR_ARGUMENT;
    }
    if (ciphertext_len < ANIMAGUS_MIN_MESSAGE_SIZE ||
        animagus_size_exceeds(ciphertext_len, ANIMAGUS_MAX_MESSAGE_SIZE)) {
        return ANIMAGUS_ERR_MESSAGE_SIZE;
    }
    return animagus_check_part_placement(ciphertext, ciphertext_len, message,
                                         ciphertext_len - ANIMAGUS_AUTH_SIZE);
}

static int animagus_auth_encrypt(const animagus_ctx *ctx, uint8_t *ciphertext,
                                 const uint8_t *message, size_t message_len,
                                 enum animagus_application application,
                                 const uint8_t *nonce, size_t nonce_len,
                                 const uint8_t *ad, size_t ad_len)
{
    uint8_t tweak[ANIMAGUS_TWEAK_SIZE];
    int result;

    result = animagus_validate_auth_encrypt(ctx, ciphertext, message,
                                            message_len);
    if (result != ANIMAGUS_OK) {
        return result;
    }
    result = animagus_make_tweak(ctx, tweak, application, nonce, nonce_len,
                                 ad, ad_len);
    if (result == ANIMAGUS_OK) {
        result = animagus_core_encrypt(ctx, ciphertext, animagus_auth_block,
                                       message,
                                       message_len + ANIMAGUS_AUTH_SIZE,
                                       tweak);
    }
    animagus_secure_zero(tweak, sizeof(tweak));
    return result;
}

static int animagus_auth_decrypt(const animagus_ctx *ctx, uint8_t *message,
                                 const uint8_t *ciphertext,
                                 size_t ciphertext_len,
                                 enum animagus_application application,
                                 const uint8_t *nonce, size_t nonce_len,
                                 const uint8_t *ad, size_t ad_len)
{
    uint8_t tweak[ANIMAGUS_TWEAK_SIZE];
    uint8_t recovered_block[ANIMAGUS_AUTH_SIZE];
    int result;

    result = animagus_validate_auth_decrypt(ctx, message, ciphertext,
                                            ciphertext_len);
    if (result != ANIMAGUS_OK) {
        return result;
    }
    result = animagus_make_tweak(ctx, tweak, application, nonce, nonce_len,
                                 ad, ad_len);
    if (result != ANIMAGUS_OK) {
        goto cleanup;
    }
    result = animagus_core_decrypt(ctx, recovered_block, message, ciphertext,
                                   ciphertext_len, tweak);
    if (result == ANIMAGUS_OK &&
        !animagus_ct_all_zero(recovered_block, sizeof(recovered_block))) {
        animagus_secure_zero(message, ciphertext_len - ANIMAGUS_AUTH_SIZE);
        result = ANIMAGUS_ERR_AUTH;
    }

cleanup:
    animagus_secure_zero(recovered_block, sizeof(recovered_block));
    animagus_secure_zero(tweak, sizeof(tweak));
    return result;
}

int animagus_aead_encrypt(const animagus_ctx *ctx, uint8_t *ciphertext,
                          const uint8_t *message, size_t message_len,
                          const uint8_t *nonce, size_t nonce_len,
                          const uint8_t *ad, size_t ad_len)
{
    return animagus_auth_encrypt(ctx, ciphertext, message, message_len,
                                 ANIMAGUS_APPLICATION_AEAD, nonce, nonce_len,
                                 ad, ad_len);
}

int animagus_aead_decrypt(const animagus_ctx *ctx, uint8_t *message,
                          const uint8_t *ciphertext, size_t ciphertext_len,
                          const uint8_t *nonce, size_t nonce_len,
                          const uint8_t *ad, size_t ad_len)
{
    return animagus_auth_decrypt(ctx, message, ciphertext, ciphertext_len,
                                 ANIMAGUS_APPLICATION_AEAD, nonce, nonce_len,
                                 ad, ad_len);
}

int animagus_tweakable_encrypt(const animagus_ctx *ctx, uint8_t *dst,
                               const uint8_t *src, size_t len,
                               const uint8_t *context, size_t context_len)
{
    uint8_t tweak[ANIMAGUS_TWEAK_SIZE];
    int result;

    result = animagus_derive_tweak(ctx, tweak, context, context_len);
    if (result == ANIMAGUS_OK) {
        result = animagus_encrypt(ctx, dst, src, len, tweak);
    }
    animagus_secure_zero(tweak, sizeof(tweak));
    return result;
}

int animagus_tweakable_decrypt(const animagus_ctx *ctx, uint8_t *dst,
                               const uint8_t *src, size_t len,
                               const uint8_t *context, size_t context_len)
{
    uint8_t tweak[ANIMAGUS_TWEAK_SIZE];
    int result;

    result = animagus_derive_tweak(ctx, tweak, context, context_len);
    if (result == ANIMAGUS_OK) {
        result = animagus_decrypt(ctx, dst, src, len, tweak);
    }
    animagus_secure_zero(tweak, sizeof(tweak));
    return result;
}

int animagus_dae_encrypt(const animagus_ctx *ctx, uint8_t *ciphertext,
                         const uint8_t *message, size_t message_len)
{
    return animagus_auth_encrypt(ctx, ciphertext, message, message_len,
                                 ANIMAGUS_APPLICATION_DAE, NULL, 0U,
                                 NULL, 0U);
}

int animagus_dae_decrypt(const animagus_ctx *ctx, uint8_t *message,
                         const uint8_t *ciphertext, size_t ciphertext_len)
{
    return animagus_auth_decrypt(ctx, message, ciphertext, ciphertext_len,
                                 ANIMAGUS_APPLICATION_DAE, NULL, 0U,
                                 NULL, 0U);
}
