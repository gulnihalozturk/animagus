#pragma once

#include "animagus.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Derived interfaces of Section 2.2 of the Animagus paper, built on the
 * Animagus-AES-v2 core without modifying it:
 *
 *   AEAD       T = MakeTweak(1, N, AD),      C = Enc(K, T, AUD || M)
 *   Tweakable  T = MakeTweak(2, empty, V),   C = Enc(K, T, M)
 *   DAE        T = MakeTweak(3, empty, empty), C = Enc(K, T, AUD || M)
 *
 * AUD is the fixed 16-byte authentication block 0^128. The authenticated
 * interfaces verify it in constant time after core decryption and return
 * the application message only when it matches.
 *
 * The paper's core theorem covers the tweakable permutation; the paper
 * states that all three derived interfaces require separate analysis of
 * derived-tweak collisions and, where applicable, verification queries.
 * This layer implements the paper's definitions and does not claim that
 * analysis.
 *
 * The AEAD and DAE tweaks are derived internally and cannot be obtained
 * through the public API, so a core decryption (animagus_decrypt with a raw
 * or animagus_derive_tweak() tweak) cannot be aimed at an authenticated
 * ciphertext's tweak. Under one key instance the remaining exposure is a
 * 2^-128 collision between truncated derived tweaks of different
 * interfaces; separate keys per interface remove it. Do not offer core
 * decryption with attacker-controlled tweaks as a service under a key that
 * also protects AEAD or DAE ciphertexts.
 */

/* Fixed authentication block length and the resulting message bounds. */
#define ANIMAGUS_AUTH_SIZE ANIMAGUS_BLOCK_SIZE
#define ANIMAGUS_AUTH_MIN_MESSAGE_SIZE ANIMAGUS_AUTH_SIZE
#define ANIMAGUS_AUTH_MAX_MESSAGE_SIZE \
    (ANIMAGUS_MAX_MESSAGE_SIZE - ANIMAGUS_AUTH_SIZE)

/*
 * Nonce-based authenticated encryption with associated data.
 *
 * message_len is ANIMAGUS_AUTH_MIN_MESSAGE_SIZE through
 * ANIMAGUS_AUTH_MAX_MESSAGE_SIZE bytes; ciphertext receives
 * message_len + ANIMAGUS_AUTH_SIZE bytes. nonce_len is 1 through
 * ANIMAGUS_MAX_FRAMED_SIZE bytes; ad_len is 0 through
 * ANIMAGUS_MAX_FRAMED_SIZE bytes, with ad == NULL valid only for ad_len == 0.
 * The application must not repeat a nonce under one key.
 *
 * message must be either ciphertext + ANIMAGUS_AUTH_SIZE (in-place form:
 * the caller placed the message at offset 16 of the ciphertext buffer) or
 * disjoint from the ciphertext range. nonce and ad may alias anything; they
 * are fully consumed before ciphertext is written. Validation errors are
 * returned before ciphertext is modified.
 */
int animagus_aead_encrypt(const animagus_ctx *ctx, uint8_t *ciphertext,
                          const uint8_t *message, size_t message_len,
                          const uint8_t *nonce, size_t nonce_len,
                          const uint8_t *ad, size_t ad_len);

/*
 * Inverse of animagus_aead_encrypt(). ciphertext_len is
 * ANIMAGUS_MIN_MESSAGE_SIZE through ANIMAGUS_MAX_MESSAGE_SIZE bytes; message
 * receives ciphertext_len - ANIMAGUS_AUTH_SIZE bytes. message must be either
 * ciphertext + ANIMAGUS_AUTH_SIZE (in-place form, which overwrites the
 * ciphertext buffer) or disjoint from the ciphertext range.
 *
 * Returns ANIMAGUS_ERR_AUTH when the recovered authentication block is not
 * AUD. The candidate plaintext is written to message during the call and
 * zeroed before the function returns on ANIMAGUS_ERR_AUTH, so no unverified
 * plaintext is returned; a concurrent reader of the caller's buffer could
 * still observe it mid-call, and the in-place form destroys the ciphertext
 * on failure. Other validation errors are returned before message is
 * modified.
 */
int animagus_aead_decrypt(const animagus_ctx *ctx, uint8_t *message,
                          const uint8_t *ciphertext, size_t ciphertext_len,
                          const uint8_t *nonce, size_t nonce_len,
                          const uint8_t *ad, size_t ad_len);

/*
 * Confidentiality-only tweakable encryption with a variable-length context
 * V of 0 through ANIMAGUS_MAX_FRAMED_SIZE bytes (context == NULL is valid
 * only for context_len == 0). The core tweak is MakeTweak(2, empty, V); the
 * message is passed to the core unchanged, so len, in-place operation, and
 * overlap follow the animagus_encrypt()/animagus_decrypt() contract.
 * Decryption performs no authentication.
 */
int animagus_tweakable_encrypt(const animagus_ctx *ctx, uint8_t *dst,
                               const uint8_t *src, size_t len,
                               const uint8_t *context, size_t context_len);
int animagus_tweakable_decrypt(const animagus_ctx *ctx, uint8_t *dst,
                               const uint8_t *src, size_t len,
                               const uint8_t *context, size_t context_len);

/*
 * Deterministic authenticated encryption. The tweak is the per-key constant
 * MakeTweak(3, empty, empty); encrypting the same message twice under one
 * key yields the same ciphertext. Lengths, buffer placement, and the
 * ANIMAGUS_ERR_AUTH behavior are those of the AEAD functions.
 */
int animagus_dae_encrypt(const animagus_ctx *ctx, uint8_t *ciphertext,
                         const uint8_t *message, size_t message_len);
int animagus_dae_decrypt(const animagus_ctx *ctx, uint8_t *message,
                         const uint8_t *ciphertext, size_t ciphertext_len);
