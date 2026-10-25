#pragma once

#include "sha3.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Two-bit role codes of the Animagus-AES-v2 keyed-hash inputs, stored in
 * FIPS 202 bit order: bit i of the role string is bit (i mod 8) of the
 * byte. The paper's literal strings 10, 01, and 00 therefore become the
 * byte values below; only their two low bits are absorbed.
 */
enum animagus_hash_role {
    ANIMAGUS_ROLE_TWEAK = 0x00,           /* bit string 00 */
    ANIMAGUS_ROLE_PLAINTEXT_TAIL = 0x01,  /* bit string 10 */
    ANIMAGUS_ROLE_CIPHERTEXT_TAIL = 0x02, /* bit string 01 */
};

#define ANIMAGUS_HASH_TWEAK_BYTES 16U
#define ANIMAGUS_HASH_MAX_FRAMED_BYTES (UINT64_C(0x1fffffffffffffff))

struct hmac_sha3_256_ctx {
    struct sha3_256_ctx inner_base;
    struct sha3_256_ctx outer_base;
};

int hmac_sha3_256_init(struct hmac_sha3_256_ctx *ctx,
                       const uint8_t *key, size_t key_len);
void hmac_sha3_256_bytes(const struct hmac_sha3_256_ctx *ctx,
                         const uint8_t *message, size_t message_len,
                         uint8_t out[SHA3_256_DIGEST_SIZE]);
void hmac_sha3_256_bytes2(const struct hmac_sha3_256_ctx *ctx,
                          const uint8_t *first, size_t first_len,
                          const uint8_t *second, size_t second_len,
                          uint8_t out[SHA3_256_DIGEST_SIZE]);

/*
 * SP 800-108r1 counter-mode KDF with HMAC-SHA3-256, one iteration:
 * HMAC_root(BE32(1) || "animagus/" || role || 0x00 || BE32(8 * key_len)).
 * role is one of "head1", "head2", "seed", "ctr", or "hash". The caller
 * keeps the first key_len bytes of out. Returns -1 for an unknown role.
 */
int hmac_sha3_256_kdf_v2(const struct hmac_sha3_256_ctx *root,
                         const char *role, size_t key_len,
                         uint8_t out[SHA3_256_DIGEST_SIZE]);

/* HMAC over tail || role || T with a literal two-bit role code. */
void hmac_sha3_256_core_v2(const struct hmac_sha3_256_ctx *ctx,
                           const uint8_t *tail, size_t tail_len,
                           enum animagus_hash_role role,
                           const uint8_t tweak[ANIMAGUS_HASH_TWEAK_BYTES],
                           uint8_t out[SHA3_256_DIGEST_SIZE]);

/*
 * HMAC over d || BE64(8 * nonce_len) || nonce || ad || 00 || 0^128, the
 * MakeTweak input of the paper. Returns -1 when either length exceeds
 * ANIMAGUS_HASH_MAX_FRAMED_BYTES, before touching the inputs.
 */
int hmac_sha3_256_tweak_v2(const struct hmac_sha3_256_ctx *ctx,
                           uint8_t application,
                           const uint8_t *nonce, size_t nonce_len,
                           const uint8_t *ad, size_t ad_len,
                           uint8_t out[SHA3_256_DIGEST_SIZE]);
