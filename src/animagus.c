#include "animagus.h"

#include "aes.h"
#include "animagus_ctr.h"
#include "hmac_sha3.h"
#include "util.h"

#include <string.h>

#define ANIMAGUS_CTX_MAGIC UINT64_C(0x414e494d41475553)

#define ANIMAGUS_KDF_AES 0x01U
#define ANIMAGUS_KDF_HASH 0x02U
#define ANIMAGUS_KDF_TWEAK 0x03U

static const uint8_t animagus_kdf_label[] = "Animagus-AES-v1/KDF";

struct animagus_ctx_impl {
    struct animagus_aes_ctx aes;
    struct hmac_sha3_256_ctx hmac;
    uint8_t tweak_key[SHA3_256_DIGEST_SIZE];
    uint64_t magic;
};

_Static_assert(sizeof(struct animagus_ctx_impl) <= ANIMAGUS_CONTEXT_BYTES,
               "Animagus implementation must fit in the public context");
_Static_assert(_Alignof(struct animagus_ctx_impl) <= _Alignof(animagus_ctx),
               "Animagus implementation alignment exceeds public context");

static void animagus_ctx_load(struct animagus_ctx_impl *impl,
                              const animagus_ctx *ctx)
{
    memcpy(impl, ctx->opaque, sizeof(*impl));
}

static void animagus_derive_subkey(
    const struct hmac_sha3_256_ctx *root, uint8_t purpose, size_t key_len,
    uint8_t out[SHA3_256_DIGEST_SIZE])
{
    const uint8_t suffix[2] = { purpose, (uint8_t)key_len };

    hmac_sha3_256_bytes2(root, animagus_kdf_label,
                         sizeof(animagus_kdf_label) - 1U,
                         suffix, sizeof(suffix), out);
}

static int animagus_validate_common(const animagus_ctx *ctx, uint8_t *dst,
                                    const uint8_t *src, size_t len,
                                    const uint8_t *tweak, size_t tweak_len,
                                    struct animagus_ctx_impl *impl)
{
    if (ctx == NULL) {
        return ANIMAGUS_ERR_ARGUMENT;
    }

    animagus_ctx_load(impl, ctx);
    if (impl->magic != ANIMAGUS_CTX_MAGIC) {
        return ANIMAGUS_ERR_STATE;
    }
    if (dst == NULL || src == NULL || (tweak == NULL && tweak_len != 0U)) {
        return ANIMAGUS_ERR_ARGUMENT;
    }
    if (len < ANIMAGUS_MIN_MESSAGE_SIZE ||
        len > ANIMAGUS_MAX_MESSAGE_SIZE) {
        return ANIMAGUS_ERR_MESSAGE_SIZE;
    }
    if (tweak_len != 0U && tweak_len != ANIMAGUS_TWEAK_SIZE) {
        return ANIMAGUS_ERR_TWEAK_SIZE;
    }
    if ((dst != src && animagus_ranges_overlap(dst, len, src, len)) ||
        animagus_ranges_overlap(dst, len, tweak, tweak_len)) {
        return ANIMAGUS_ERR_OVERLAP;
    }
    return ANIMAGUS_OK;
}

int animagus_init(animagus_ctx *ctx, const uint8_t *key, size_t key_len)
{
    enum animagus_backend backend = animagus_aes_hardware_available() ?
        ANIMAGUS_BACKEND_HARDWARE : ANIMAGUS_BACKEND_PORTABLE;

    return animagus_init_ex(ctx, key, key_len, backend);
}

int animagus_init_ex(animagus_ctx *ctx, const uint8_t *key, size_t key_len,
                     enum animagus_backend backend)
{
    struct animagus_ctx_impl temporary = { 0 };
    struct hmac_sha3_256_ctx root_hmac = { 0 };
    uint8_t aes_key[SHA3_256_DIGEST_SIZE] = { 0 };
    uint8_t hash_key[SHA3_256_DIGEST_SIZE] = { 0 };
    uint8_t tweak_key[SHA3_256_DIGEST_SIZE] = { 0 };
    enum animagus_aes_backend aes_backend;
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
    animagus_derive_subkey(&root_hmac, ANIMAGUS_KDF_AES, key_len, aes_key);
    animagus_derive_subkey(&root_hmac, ANIMAGUS_KDF_HASH, key_len, hash_key);
    animagus_derive_subkey(&root_hmac, ANIMAGUS_KDF_TWEAK, key_len, tweak_key);

    if (animagus_aes_setkey(&temporary.aes, aes_key, key_len,
                            aes_backend) != 0 ||
        hmac_sha3_256_init(&temporary.hmac, hash_key,
                           sizeof(hash_key)) != 0) {
        result = ANIMAGUS_ERR_BACKEND;
        goto cleanup;
    }
    memcpy(temporary.tweak_key, tweak_key, sizeof(temporary.tweak_key));
    temporary.magic = ANIMAGUS_CTX_MAGIC;
    memset(ctx->opaque, 0, sizeof(ctx->opaque));
    memcpy(ctx->opaque, &temporary, sizeof(temporary));

cleanup:
    animagus_secure_zero(tweak_key, sizeof(tweak_key));
    animagus_secure_zero(hash_key, sizeof(hash_key));
    animagus_secure_zero(aes_key, sizeof(aes_key));
    animagus_secure_zero(&root_hmac, sizeof(root_hmac));
    animagus_secure_zero(&temporary, sizeof(temporary));
    return result;
}

int animagus_encrypt(const animagus_ctx *ctx, uint8_t *dst,
                     const uint8_t *src, size_t len,
                     const uint8_t *tweak, size_t tweak_len)
{
    struct animagus_ctx_impl impl = { 0 };
    uint8_t x[32], a1[16], a2[16], f[16], b[16], j[16];
    uint8_t first[16], second[16], tmp[16];
    size_t index;
    int result;

    result = animagus_validate_common(ctx, dst, src, len, tweak, tweak_len,
                                      &impl);
    if (result != ANIMAGUS_OK) {
        goto cleanup;
    }

    memcpy(first, src, sizeof(first));
    memcpy(second, src + sizeof(first), sizeof(second));

    hmac_sha3_256_animagus_v1(&impl.hmac, src + 32U, len - 32U,
                              ANIMAGUS_HASH_PLAINTEXT,
                              tweak, tweak_len, x);
    memcpy(a1, x, sizeof(a1));
    memcpy(a2, x + sizeof(a1), sizeof(a2));

    for (index = 0; index < sizeof(tmp); ++index) {
        tmp[index] = first[index] ^ a2[index];
    }
    animagus_aes_encrypt_block(&impl.aes, f, tmp);

    for (index = 0; index < sizeof(tmp); ++index) {
        tmp[index] = second[index] ^ a1[index] ^ f[index];
    }
    animagus_aes_encrypt_block(&impl.aes, b, tmp);

    for (index = 0; index < sizeof(j); ++index) {
        j[index] = f[index] ^ b[index];
    }
    animagus_ctr_crypt(&impl.aes, dst + 32U, src + 32U, len - 32U, j);

    hmac_sha3_256_animagus_v1(&impl.hmac, dst + 32U, len - 32U,
                              ANIMAGUS_HASH_CIPHERTEXT,
                              tweak, tweak_len, x);
    memcpy(a1, x, sizeof(a1));
    memcpy(a2, x + sizeof(a1), sizeof(a2));

    for (index = 0; index < sizeof(tmp); ++index) {
        tmp[index] = b[index] ^ a1[index];
    }
    animagus_aes_encrypt_block(&impl.aes, second, tmp);

    for (index = 0; index < sizeof(tmp); ++index) {
        tmp[index] = f[index] ^ a2[index] ^ second[index];
    }
    animagus_aes_encrypt_block(&impl.aes, first, tmp);

    memcpy(dst, first, sizeof(first));
    memcpy(dst + sizeof(first), second, sizeof(second));

cleanup:
    animagus_secure_zero(tmp, sizeof(tmp));
    animagus_secure_zero(second, sizeof(second));
    animagus_secure_zero(first, sizeof(first));
    animagus_secure_zero(j, sizeof(j));
    animagus_secure_zero(b, sizeof(b));
    animagus_secure_zero(f, sizeof(f));
    animagus_secure_zero(a2, sizeof(a2));
    animagus_secure_zero(a1, sizeof(a1));
    animagus_secure_zero(x, sizeof(x));
    animagus_secure_zero(&impl, sizeof(impl));
    return result;
}

int animagus_decrypt(const animagus_ctx *ctx, uint8_t *dst,
                     const uint8_t *src, size_t len,
                     const uint8_t *tweak, size_t tweak_len)
{
    struct animagus_ctx_impl impl = { 0 };
    uint8_t x[32], a1[16], a2[16], a3[16], a4[16];
    uint8_t f[16], b[16], j[16], c1[16], c2[16];
    uint8_t first[16], second[16], tmp[16];
    size_t index;
    int result;

    result = animagus_validate_common(ctx, dst, src, len, tweak, tweak_len,
                                      &impl);
    if (result != ANIMAGUS_OK) {
        goto cleanup;
    }

    memcpy(c1, src, sizeof(c1));
    memcpy(c2, src + sizeof(c1), sizeof(c2));

    hmac_sha3_256_animagus_v1(&impl.hmac, src + 32U, len - 32U,
                              ANIMAGUS_HASH_CIPHERTEXT,
                              tweak, tweak_len, x);
    memcpy(a1, x, sizeof(a1));
    memcpy(a2, x + sizeof(a1), sizeof(a2));

    animagus_aes_decrypt_block(&impl.aes, tmp, c1);
    for (index = 0; index < sizeof(f); ++index) {
        f[index] = tmp[index] ^ a2[index] ^ c2[index];
    }

    animagus_aes_decrypt_block(&impl.aes, tmp, c2);
    for (index = 0; index < sizeof(b); ++index) {
        b[index] = tmp[index] ^ a1[index];
    }

    for (index = 0; index < sizeof(j); ++index) {
        j[index] = f[index] ^ b[index];
    }
    animagus_ctr_crypt(&impl.aes, dst + 32U, src + 32U, len - 32U, j);

    hmac_sha3_256_animagus_v1(&impl.hmac, dst + 32U, len - 32U,
                              ANIMAGUS_HASH_PLAINTEXT,
                              tweak, tweak_len, x);
    memcpy(a3, x, sizeof(a3));
    memcpy(a4, x + sizeof(a3), sizeof(a4));

    animagus_aes_decrypt_block(&impl.aes, tmp, b);
    for (index = 0; index < sizeof(second); ++index) {
        second[index] = tmp[index] ^ a3[index] ^ f[index];
    }

    animagus_aes_decrypt_block(&impl.aes, tmp, f);
    for (index = 0; index < sizeof(first); ++index) {
        first[index] = tmp[index] ^ a4[index];
    }

    memcpy(dst, first, sizeof(first));
    memcpy(dst + sizeof(first), second, sizeof(second));

cleanup:
    animagus_secure_zero(tmp, sizeof(tmp));
    animagus_secure_zero(second, sizeof(second));
    animagus_secure_zero(first, sizeof(first));
    animagus_secure_zero(c2, sizeof(c2));
    animagus_secure_zero(c1, sizeof(c1));
    animagus_secure_zero(j, sizeof(j));
    animagus_secure_zero(b, sizeof(b));
    animagus_secure_zero(f, sizeof(f));
    animagus_secure_zero(a4, sizeof(a4));
    animagus_secure_zero(a3, sizeof(a3));
    animagus_secure_zero(a2, sizeof(a2));
    animagus_secure_zero(a1, sizeof(a1));
    animagus_secure_zero(x, sizeof(x));
    animagus_secure_zero(&impl, sizeof(impl));
    return result;
}

int animagus_derive_tweak(const animagus_ctx *ctx,
                          uint8_t tweak[ANIMAGUS_TWEAK_SIZE],
                          const uint8_t *nonce, size_t nonce_len,
                          const uint8_t *ad, size_t ad_len)
{
    struct animagus_ctx_impl impl = { 0 };
    struct hmac_sha3_256_ctx tweak_hmac = { 0 };
    uint8_t digest[32];
    int result = ANIMAGUS_OK;

    if (ctx == NULL) {
        return ANIMAGUS_ERR_ARGUMENT;
    }
    animagus_ctx_load(&impl, ctx);
    if (impl.magic != ANIMAGUS_CTX_MAGIC) {
        result = ANIMAGUS_ERR_STATE;
        goto cleanup;
    }
    if (tweak == NULL || (nonce == NULL && nonce_len != 0U) ||
        (ad == NULL && ad_len != 0U)) {
        result = ANIMAGUS_ERR_ARGUMENT;
        goto cleanup;
    }

    if (hmac_sha3_256_init(&tweak_hmac, impl.tweak_key,
                           sizeof(impl.tweak_key)) != 0) {
        result = ANIMAGUS_ERR_BACKEND;
        goto cleanup;
    }
    hmac_sha3_256_tweak_v1(&tweak_hmac, nonce, nonce_len,
                           ad, ad_len, digest);
    memcpy(tweak, digest, ANIMAGUS_TWEAK_SIZE);

cleanup:
    animagus_secure_zero(digest, sizeof(digest));
    animagus_secure_zero(&tweak_hmac, sizeof(tweak_hmac));
    animagus_secure_zero(&impl, sizeof(impl));
    return result;
}

void animagus_clear(animagus_ctx *ctx)
{
    if (ctx != NULL) {
        animagus_secure_zero(ctx, sizeof(*ctx));
    }
}
