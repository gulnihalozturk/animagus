#pragma once

#include "animagus.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Library-internal entry points shared by the public core API and the
 * derived interfaces. They operate on the core input split as a 16-byte
 * head block followed by the remaining bytes, so a caller can supply the
 * head from a separate buffer (for example the fixed authentication block)
 * without assembling a contiguous copy.
 *
 * These functions check only the context and the total length. Every other
 * precondition below is the caller's responsibility and is validated by the
 * public entry point according to its own documented contract.
 */

/* ANIMAGUS_OK, ANIMAGUS_ERR_ARGUMENT for NULL, or ANIMAGUS_ERR_STATE. */
int animagus_ctx_state(const animagus_ctx *ctx);

/*
 * Encrypts head || rest (len bytes in total, rest has len - 16) into dst.
 * head is copied before anything is written and may alias anything. rest
 * must be either dst + 16 or disjoint from dst; tweak must be disjoint
 * from dst. len must be a valid core message length.
 */
int animagus_core_encrypt(const animagus_ctx *ctx, uint8_t *dst,
                          const uint8_t head[ANIMAGUS_BLOCK_SIZE],
                          const uint8_t *rest, size_t len,
                          const uint8_t tweak[ANIMAGUS_TWEAK_SIZE]);

/*
 * Decrypts src (len bytes). The recovered first block is written to
 * head_out after every other write; the remaining len - 16 recovered bytes
 * are written to rest_out. rest_out must be either src + 16 or disjoint
 * from src; head_out must be disjoint from rest_out; tweak must be disjoint
 * from rest_out. len must be a valid core message length.
 */
int animagus_core_decrypt(const animagus_ctx *ctx,
                          uint8_t head_out[ANIMAGUS_BLOCK_SIZE],
                          uint8_t *rest_out, const uint8_t *src, size_t len,
                          const uint8_t tweak[ANIMAGUS_TWEAK_SIZE]);

/*
 * Application identifier d of the paper's MakeTweak. The identifier is fixed
 * by the interface that calls MakeTweak; only the tweakable form (d = 2) is
 * reachable from the public API, through animagus_derive_tweak().
 */
enum animagus_application {
    ANIMAGUS_APPLICATION_AEAD = 1,
    ANIMAGUS_APPLICATION_TWEAKABLE = 2,
    ANIMAGUS_APPLICATION_DAE = 3,
};

/*
 * MakeTweak(d, N, AD): the first 16 bytes of HMAC-SHA3-256 under Khash over
 * BE8(d) || BE64(8 * nonce_len) || nonce || ad || 00 || 0^128. The paper's
 * interface shapes are enforced: AEAD needs nonce_len >= 1; the tweakable
 * form needs nonce_len == 0; DAE needs nonce_len == 0 and ad_len == 0.
 * Both lengths are limited to ANIMAGUS_MAX_FRAMED_SIZE bytes. Violations
 * and NULL pointers with nonzero lengths return ANIMAGUS_ERR_ARGUMENT.
 */
int animagus_make_tweak(const animagus_ctx *ctx,
                        uint8_t tweak[ANIMAGUS_TWEAK_SIZE],
                        enum animagus_application application,
                        const uint8_t *nonce, size_t nonce_len,
                        const uint8_t *ad, size_t ad_len);
