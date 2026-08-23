#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "aes_linux.h"

enum animagus_aes_backend {
    ANIMAGUS_AES_PORTABLE = 0,
    ANIMAGUS_AES_HARDWARE = 1,
};

struct animagus_aes_ctx {
    _Alignas(32) struct crypto_aes_ctx schedule;
    enum animagus_aes_backend backend;
};

int animagus_aes_setkey(struct animagus_aes_ctx *ctx,
                        const uint8_t *key, size_t key_len,
                        enum animagus_aes_backend backend);
void animagus_aes_encrypt_block(const struct animagus_aes_ctx *ctx,
                                uint8_t out[16], const uint8_t in[16]);
void animagus_aes_decrypt_block(const struct animagus_aes_ctx *ctx,
                                uint8_t out[16], const uint8_t in[16]);
void animagus_aes_encrypt_blocks(const struct animagus_aes_ctx *ctx,
                                 uint8_t *out, const uint8_t *in,
                                 size_t block_count);
bool animagus_aes_hardware_available(void);
