#pragma once

#include <stddef.h>
#include <stdint.h>

#define ANIMAGUS_BLOCK_SIZE 16U
#define ANIMAGUS_TWEAK_SIZE 16U
#define ANIMAGUS_MIN_MESSAGE_SIZE 32U
#define ANIMAGUS_CONTEXT_BYTES 4096U
#define ANIMAGUS_MAX_MESSAGE_SIZE UINT64_C(4503599627370496) /* 2^52 */
/* The paper bounds nonce, associated data, and context by |N|, |AD| < 2^64
 * bits (the nonce length is framed in bits), so each is limited to
 * 2^61 - 1 bytes. */
#define ANIMAGUS_MAX_FRAMED_SIZE UINT64_C(2305843009213693951)
#define ANIMAGUS_PROFILE_NAME "Animagus-AES-v2"
#define ANIMAGUS_PROFILE_VERSION 2U

enum animagus_status {
    ANIMAGUS_OK = 0,
    ANIMAGUS_ERR_ARGUMENT = -1,
    ANIMAGUS_ERR_KEY_SIZE = -2,
    ANIMAGUS_ERR_MESSAGE_SIZE = -3,
    ANIMAGUS_ERR_OVERLAP = -4,
    ANIMAGUS_ERR_BACKEND = -5,
    ANIMAGUS_ERR_STATE = -6,
    /* Returned only by the authenticated interfaces in animagus_derived.h.
     * The value -7 was ANIMAGUS_ERR_TWEAK_SIZE in the retired v1 profile. */
    ANIMAGUS_ERR_AUTH = -7,
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
 * The core API below is the tweakable permutation of the paper. The derived
 * AEAD, tweakable-encryption, and DAE interfaces of the paper's Section 2.2
 * are declared in animagus_derived.h.
 *
 * Key is 16, 24, or 32 bytes (AES-128/192/256). A context must be
 * initialized successfully before use. The master key is used only to
 * derive the five same-length working keys Khead1, Khead2, Kseed, Kctr,
 * and Khash with the SP 800-108r1 counter-mode KDF over HMAC-SHA3-256.
 * animagus_init() is animagus_init_ex(..., ANIMAGUS_BACKEND_AUTO). A
 * failed initialization leaves a previously initialized context unchanged.
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
 * ciphertext length equals plaintext length. The paper admits any bit
 * length in that range; this implementation accepts whole bytes only. On
 * that sub-domain it agrees with a bit-granular implementation that reads
 * the paper's bit strings the same way (see the profile document).
 *
 * tweak is always exactly ANIMAGUS_TWEAK_SIZE bytes and must not be NULL.
 * It is either the output of animagus_derive_tweak() (the paper's
 * tweakable-encryption interface with a variable-length context) or any
 * caller-chosen 16-byte value (the paper's raw tweakable interface).
 *
 * Core decryption with a caller-controlled tweak is an unauthenticated
 * decryption oracle. The paper requires that it not provide a bypass for
 * the authenticated interfaces under the same key instance. The AEAD and
 * DAE tweaks cannot be produced through this API, so with one key the
 * residual exposure is a 2^-128 truncated-tweak collision per tweak pair;
 * using separate keys for the core and the authenticated interfaces removes
 * it entirely.
 *
 * Ciphertexts from the retired Animagus-AES-v1 profile and from the
 * pre-v1 literal implementation of the February 2026 paper are incompatible
 * with this profile. Animagus is not authenticated encryption, so
 * applications must bind ANIMAGUS_PROFILE_NAME and ANIMAGUS_PROFILE_VERSION
 * to stored ciphertext metadata rather than probing profiles during
 * decryption.
 *
 * dst == src operates in place; otherwise dst and src must be disjoint.
 * dst must also be disjoint from the tweak, because the tweak is hashed
 * after part of dst is written. A tweak may overlap src, and adjacent
 * ranges are fine. Argument, state, length, and overlap errors are
 * rejected before dst is modified.
 */
int animagus_encrypt(const animagus_ctx *ctx, uint8_t *dst,
                     const uint8_t *src, size_t len,
                     const uint8_t tweak[ANIMAGUS_TWEAK_SIZE]);
int animagus_decrypt(const animagus_ctx *ctx, uint8_t *dst,
                     const uint8_t *src, size_t len,
                     const uint8_t tweak[ANIMAGUS_TWEAK_SIZE]);

/*
 * The paper's MakeTweak(2, empty, V) for a variable-length context V: the
 * first 16 bytes of HMAC-SHA3-256 under Khash over
 * 0x02 || BE64(0) || V || 00 || 0^128, where 00 is a literal two-bit role
 * code. This is the only derived tweak the paper defines for direct use
 * with the core. The AEAD (d = 1) and DAE (d = 3) tweaks are derived inside
 * animagus_derived.c and are deliberately not exposed, so that a core
 * decryption can never be pointed at an authenticated ciphertext's tweak.
 *
 * context_len is 0 through ANIMAGUS_MAX_FRAMED_SIZE bytes; context == NULL
 * is valid only with context_len == 0. tweak may overlap context; it is
 * written only after the context is fully read. Violations return
 * ANIMAGUS_ERR_ARGUMENT.
 */
int animagus_derive_tweak(const animagus_ctx *ctx,
                          uint8_t tweak[ANIMAGUS_TWEAK_SIZE],
                          const uint8_t *context, size_t context_len);

/* Zeroizes the context, including key material. */
void animagus_clear(animagus_ctx *ctx);
