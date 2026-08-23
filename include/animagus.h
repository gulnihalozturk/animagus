#pragma once

#include <stddef.h>
#include <stdint.h>

#define ANIMAGUS_BLOCK_SIZE 16U
#define ANIMAGUS_TWEAK_SIZE 16U
#define ANIMAGUS_MIN_MESSAGE_SIZE 32U
#define ANIMAGUS_CONTEXT_BYTES 1024U
#define ANIMAGUS_MAX_MESSAGE_SIZE UINT64_C(4503599627370496) /* 2^52 */
#define ANIMAGUS_PROFILE_NAME "Animagus-AES-v1"
#define ANIMAGUS_PROFILE_VERSION 1U

enum animagus_status {
    ANIMAGUS_OK = 0,
    ANIMAGUS_ERR_ARGUMENT = -1,
    ANIMAGUS_ERR_KEY_SIZE = -2,
    ANIMAGUS_ERR_MESSAGE_SIZE = -3,
    ANIMAGUS_ERR_OVERLAP = -4,
    ANIMAGUS_ERR_BACKEND = -5,
    ANIMAGUS_ERR_STATE = -6,
    ANIMAGUS_ERR_TWEAK_SIZE = -7,
};

enum animagus_backend {
    ANIMAGUS_BACKEND_AUTO = 0,
    ANIMAGUS_BACKEND_PORTABLE = 1,
    ANIMAGUS_BACKEND_HARDWARE = 2,
};

typedef struct animagus_ctx {
    _Alignas(32) uint8_t opaque[ANIMAGUS_CONTEXT_BYTES];
} animagus_ctx;

/*
 * Key is 16, 24, or 32 bytes (AES-128/192/256). A context must be
 * initialized successfully before use. The master key is expanded into
 * domain-separated AES, core-HMAC, and tweak-HMAC keys. animagus_init() is
 * animagus_init_ex(..., ANIMAGUS_BACKEND_AUTO). A failed initialization
 * leaves a previously initialized context unchanged.
 *
 * Concurrent encrypt/decrypt operations using an unchanged initialized
 * context are supported. Callers must provide exclusive synchronization
 * around initialization, reinitialization, or clearing.
 */
int animagus_init(animagus_ctx *ctx, const uint8_t *key, size_t key_len);
int animagus_init_ex(animagus_ctx *ctx, const uint8_t *key, size_t key_len,
                     enum animagus_backend backend);

/*
 * len is ANIMAGUS_MIN_MESSAGE_SIZE through ANIMAGUS_MAX_MESSAGE_SIZE bytes;
 * ciphertext length equals plaintext length.
 *
 * tweak_len is either 0 or exactly ANIMAGUS_TWEAK_SIZE; other lengths
 * fail with ANIMAGUS_ERR_TWEAK_SIZE. A 16-byte tweak is normally the value
 * produced by animagus_derive_tweak(); an empty tweak selects deterministic
 * (DAE-style) usage. Animagus-AES-v1 injectively frames the tweak length, so
 * both forms may safely share a key and context.
 *
 * Ciphertexts from the pre-v1 literal-paper profile are incompatible with
 * this profile. Animagus is not authenticated encryption, so applications
 * must bind ANIMAGUS_PROFILE_VERSION to stored ciphertext metadata rather
 * than probing profiles during decryption.
 *
 * dst == src operates in place; otherwise dst and src must be disjoint.
 * dst must also be disjoint from a nonempty tweak, because the tweak is
 * hashed after part of dst is written. A tweak may overlap src, and
 * adjacent ranges are fine. tweak == NULL is valid only with
 * tweak_len == 0. Argument, state, length, and overlap errors are
 * rejected before dst is modified.
 */
int animagus_encrypt(const animagus_ctx *ctx, uint8_t *dst,
                     const uint8_t *src, size_t len,
                     const uint8_t *tweak, size_t tweak_len);
int animagus_decrypt(const animagus_ctx *ctx, uint8_t *dst,
                     const uint8_t *src, size_t len,
                     const uint8_t *tweak, size_t tweak_len);

/*
 * Derives the Animagus-AES-v1 accordion tweak with the dedicated tweak
 * subkey and an injective frame containing the profile label, uint64-be
 * nonce/ad lengths, nonce, and ad. The first 16 HMAC-SHA3-256 output bytes
 * are written to tweak[ANIMAGUS_TWEAK_SIZE]. nonce == NULL is valid only
 * with nonce_len == 0, likewise for ad. tweak may overlap nonce or ad; it
 * is written only after both are fully read.
 */
int animagus_derive_tweak(const animagus_ctx *ctx,
                          uint8_t tweak[ANIMAGUS_TWEAK_SIZE],
                          const uint8_t *nonce, size_t nonce_len,
                          const uint8_t *ad, size_t ad_len);

/* Zeroizes the context, including key material. */
void animagus_clear(animagus_ctx *ctx);
