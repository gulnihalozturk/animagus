/*
 * The portable AES implementation is vendored unchanged from Linux's
 * scalar aes_ti.c transform; see third_party/linux-kernel/ for its notices.
 */
#include "aes.h"

#include <limits.h>

#if defined(__aarch64__) && (defined(__linux__) || defined(__ANDROID__))
#include <asm/hwcap.h>
#include <sys/auxv.h>
#endif

#if defined(__aarch64__)
static int animagus_aes_rounds(const struct animagus_aes_ctx *ctx)
{
    return 6 + (int)(ctx->schedule.key_length / 4U);
}
#endif

int animagus_aes_setkey(struct animagus_aes_ctx *ctx, const uint8_t *key,
                        size_t key_len, enum animagus_aes_backend backend)
{
    if (key_len != AES_KEYSIZE_128 && key_len != AES_KEYSIZE_192 &&
        key_len != AES_KEYSIZE_256) {
        return -1;
    }
    if (backend == ANIMAGUS_AES_HARDWARE) {
        if (!animagus_aes_hardware_available() ||
            aesti_expand_key(&ctx->schedule, key,
                             (unsigned int)key_len) != 0) {
            return -1;
        }
    } else if (backend == ANIMAGUS_AES_PORTABLE) {
        if (aesti_set_key(&ctx->schedule, key,
                          (unsigned int)key_len) != 0) {
            return -1;
        }
    } else {
        return -1;
    }
    ctx->backend = backend;
    return 0;
}

void animagus_aes_encrypt_block(const struct animagus_aes_ctx *ctx,
                                uint8_t out[16], const uint8_t in[16])
{
    if (ctx->backend == ANIMAGUS_AES_HARDWARE) {
#if defined(__x86_64__)
        aesni_ecb_enc(&ctx->schedule, out, in, AES_BLOCK_SIZE);
#elif defined(__aarch64__)
        ce_aes_ecb_encrypt(out, in,
                           (const uint8_t *)ctx->schedule.key_enc,
                           animagus_aes_rounds(ctx), 1);
#endif
    } else {
        aesti_encrypt(&ctx->schedule, out, in);
    }
}

void animagus_aes_decrypt_block(const struct animagus_aes_ctx *ctx,
                                uint8_t out[16], const uint8_t in[16])
{
    if (ctx->backend == ANIMAGUS_AES_HARDWARE) {
#if defined(__x86_64__)
        aesni_ecb_dec(&ctx->schedule, out, in, AES_BLOCK_SIZE);
#elif defined(__aarch64__)
        ce_aes_ecb_decrypt(out, in,
                           (const uint8_t *)ctx->schedule.key_dec,
                           animagus_aes_rounds(ctx), 1);
#endif
    } else {
        aesti_decrypt(&ctx->schedule, out, in);
    }
}

void animagus_aes_encrypt_blocks(const struct animagus_aes_ctx *ctx,
                                 uint8_t *out, const uint8_t *in,
                                 size_t block_count)
{
    if (ctx->backend == ANIMAGUS_AES_HARDWARE) {
        while (block_count != 0U) {
            size_t chunk = block_count;
            size_t byte_count;

            if (chunk > (size_t)INT_MAX) {
                chunk = (size_t)INT_MAX;
            }
            byte_count = chunk * AES_BLOCK_SIZE;
#if defined(__x86_64__)
            aesni_ecb_enc(&ctx->schedule, out, in, byte_count);
#elif defined(__aarch64__)
            ce_aes_ecb_encrypt(out, in,
                               (const uint8_t *)ctx->schedule.key_enc,
                               animagus_aes_rounds(ctx), (int)chunk);
#endif
            out += byte_count;
            in += byte_count;
            block_count -= chunk;
        }
    } else {
        size_t index;

        for (index = 0; index < block_count; ++index) {
            aesti_encrypt(&ctx->schedule, out + AES_BLOCK_SIZE * index,
                          in + AES_BLOCK_SIZE * index);
        }
    }
}

bool animagus_aes_hardware_available(void)
{
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
    __builtin_cpu_init();
    return __builtin_cpu_supports("aes") != 0;
#elif defined(__aarch64__) && (defined(__linux__) || defined(__ANDROID__))
    return (getauxval(AT_HWCAP) & HWCAP_AES) != 0UL;
#else
    return false;
#endif
}
