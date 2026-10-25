#include "animagus_derived.h"
#include "animagus_testvecs.h"
#include "test_common.h"
#include "../src/animagus_internal.h"
#include "../src/util.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define ASSERT_TRUE(condition) ASSERT_EQ((condition), 1)

static void fill_pattern(uint8_t *bytes, size_t length, uint8_t seed)
{
    size_t index;

    for (index = 0; index < length; ++index) {
        bytes[index] = (uint8_t)(seed + index * 29U);
    }
}

static int is_all_zero(const uint8_t *bytes, size_t length)
{
    size_t index;

    for (index = 0; index < length; ++index) {
        if (bytes[index] != 0U) {
            return 0;
        }
    }
    return 1;
}

static void check_aead_vector(const struct animagus_aead_testvec *vector)
{
    const size_t message_len = vector->message.len;
    const size_t ciphertext_len = vector->ciphertext.len;
    uint8_t *ciphertext = malloc(ciphertext_len);
    uint8_t *message = malloc(message_len);
    uint8_t *buffer = malloc(ciphertext_len);
    animagus_ctx ctx;

    ASSERT_TRUE(ciphertext != NULL);
    ASSERT_TRUE(message != NULL);
    ASSERT_TRUE(buffer != NULL);
    ASSERT_EQ(ciphertext_len, message_len + ANIMAGUS_AUTH_SIZE);
    ASSERT_EQ(animagus_init_ex(&ctx, vector->key.data, vector->key.len,
                               ANIMAGUS_BACKEND_PORTABLE), ANIMAGUS_OK);

    ASSERT_EQ(animagus_aead_encrypt(&ctx, ciphertext, vector->message.data,
                                    message_len, vector->nonce.data,
                                    vector->nonce.len, vector->ad.data,
                                    vector->ad.len), ANIMAGUS_OK);
    ASSERT_MEMEQ(ciphertext, vector->ciphertext.data, ciphertext_len);

    ASSERT_EQ(animagus_aead_decrypt(&ctx, message, vector->ciphertext.data,
                                    ciphertext_len, vector->nonce.data,
                                    vector->nonce.len, vector->ad.data,
                                    vector->ad.len), ANIMAGUS_OK);
    ASSERT_MEMEQ(message, vector->message.data, message_len);

    /* In-place forms: the message lives at offset 16 of the buffer. */
    fill_pattern(buffer, ciphertext_len, 0x5aU);
    memcpy(buffer + ANIMAGUS_AUTH_SIZE, vector->message.data, message_len);
    ASSERT_EQ(animagus_aead_encrypt(&ctx, buffer, buffer + ANIMAGUS_AUTH_SIZE,
                                    message_len, vector->nonce.data,
                                    vector->nonce.len, vector->ad.data,
                                    vector->ad.len), ANIMAGUS_OK);
    ASSERT_MEMEQ(buffer, vector->ciphertext.data, ciphertext_len);
    ASSERT_EQ(animagus_aead_decrypt(&ctx, buffer + ANIMAGUS_AUTH_SIZE, buffer,
                                    ciphertext_len, vector->nonce.data,
                                    vector->nonce.len, vector->ad.data,
                                    vector->ad.len), ANIMAGUS_OK);
    ASSERT_MEMEQ(buffer + ANIMAGUS_AUTH_SIZE, vector->message.data,
                 message_len);

    animagus_clear(&ctx);
    free(buffer);
    free(message);
    free(ciphertext);
}

static void check_aead_vectors(const struct animagus_aead_testvec *vectors,
                               size_t count)
{
    size_t index;

    for (index = 0; index < count; ++index) {
        check_aead_vector(&vectors[index]);
    }
}

static void check_dae_vector(const struct animagus_dae_testvec *vector)
{
    const size_t message_len = vector->message.len;
    const size_t ciphertext_len = vector->ciphertext.len;
    uint8_t *ciphertext = malloc(ciphertext_len);
    uint8_t *message = malloc(message_len);
    uint8_t *buffer = malloc(ciphertext_len);
    animagus_ctx ctx;

    ASSERT_TRUE(ciphertext != NULL);
    ASSERT_TRUE(message != NULL);
    ASSERT_TRUE(buffer != NULL);
    ASSERT_EQ(ciphertext_len, message_len + ANIMAGUS_AUTH_SIZE);
    ASSERT_EQ(animagus_init_ex(&ctx, vector->key.data, vector->key.len,
                               ANIMAGUS_BACKEND_PORTABLE), ANIMAGUS_OK);

    ASSERT_EQ(animagus_dae_encrypt(&ctx, ciphertext, vector->message.data,
                                   message_len), ANIMAGUS_OK);
    ASSERT_MEMEQ(ciphertext, vector->ciphertext.data, ciphertext_len);
    ASSERT_EQ(animagus_dae_decrypt(&ctx, message, vector->ciphertext.data,
                                   ciphertext_len), ANIMAGUS_OK);
    ASSERT_MEMEQ(message, vector->message.data, message_len);

    memcpy(buffer + ANIMAGUS_AUTH_SIZE, vector->message.data, message_len);
    ASSERT_EQ(animagus_dae_encrypt(&ctx, buffer, buffer + ANIMAGUS_AUTH_SIZE,
                                   message_len), ANIMAGUS_OK);
    ASSERT_MEMEQ(buffer, vector->ciphertext.data, ciphertext_len);
    ASSERT_EQ(animagus_dae_decrypt(&ctx, buffer + ANIMAGUS_AUTH_SIZE, buffer,
                                   ciphertext_len), ANIMAGUS_OK);
    ASSERT_MEMEQ(buffer + ANIMAGUS_AUTH_SIZE, vector->message.data,
                 message_len);

    animagus_clear(&ctx);
    free(buffer);
    free(message);
    free(ciphertext);
}

static void check_dae_vectors(const struct animagus_dae_testvec *vectors,
                              size_t count)
{
    size_t index;

    for (index = 0; index < count; ++index) {
        check_dae_vector(&vectors[index]);
    }
}

static void check_tweakable_vector(
    const struct animagus_tweakable_testvec *vector)
{
    const size_t len = vector->plaintext.len;
    uint8_t *ciphertext = malloc(len);
    uint8_t *recovered = malloc(len);
    animagus_ctx ctx;

    ASSERT_TRUE(ciphertext != NULL);
    ASSERT_TRUE(recovered != NULL);
    ASSERT_EQ(vector->ciphertext.len, len);
    ASSERT_EQ(animagus_init_ex(&ctx, vector->key.data, vector->key.len,
                               ANIMAGUS_BACKEND_PORTABLE), ANIMAGUS_OK);

    ASSERT_EQ(animagus_tweakable_encrypt(&ctx, ciphertext,
                                         vector->plaintext.data, len,
                                         vector->context.data,
                                         vector->context.len), ANIMAGUS_OK);
    ASSERT_MEMEQ(ciphertext, vector->ciphertext.data, len);
    ASSERT_EQ(animagus_tweakable_decrypt(&ctx, recovered,
                                         vector->ciphertext.data, len,
                                         vector->context.data,
                                         vector->context.len), ANIMAGUS_OK);
    ASSERT_MEMEQ(recovered, vector->plaintext.data, len);

    /* In place, as for the core. */
    memcpy(recovered, vector->plaintext.data, len);
    ASSERT_EQ(animagus_tweakable_encrypt(&ctx, recovered, recovered, len,
                                         vector->context.data,
                                         vector->context.len), ANIMAGUS_OK);
    ASSERT_MEMEQ(recovered, vector->ciphertext.data, len);
    ASSERT_EQ(animagus_tweakable_decrypt(&ctx, recovered, recovered, len,
                                         vector->context.data,
                                         vector->context.len), ANIMAGUS_OK);
    ASSERT_MEMEQ(recovered, vector->plaintext.data, len);

    animagus_clear(&ctx);
    free(recovered);
    free(ciphertext);
}

static void check_tweakable_vectors(
    const struct animagus_tweakable_testvec *vectors, size_t count)
{
    size_t index;

    for (index = 0; index < count; ++index) {
        check_tweakable_vector(&vectors[index]);
    }
}

static void check_interfaces_match_core_composition(void)
{
    const uint8_t key[32] = { 0 };
    uint8_t nonce[12], ad[9], context[21];
    uint8_t message[40];
    uint8_t core_input[sizeof(message) + ANIMAGUS_AUTH_SIZE] = { 0 };
    uint8_t expected[sizeof(core_input)];
    uint8_t actual[sizeof(core_input)];
    uint8_t tweak[ANIMAGUS_TWEAK_SIZE];
    animagus_ctx ctx;

    fill_pattern(nonce, sizeof(nonce), 0x01U);
    fill_pattern(ad, sizeof(ad), 0x02U);
    fill_pattern(context, sizeof(context), 0x03U);
    fill_pattern(message, sizeof(message), 0x04U);
    memcpy(core_input + ANIMAGUS_AUTH_SIZE, message, sizeof(message));
    ASSERT_EQ(animagus_init_ex(&ctx, key, sizeof(key),
                               ANIMAGUS_BACKEND_PORTABLE), ANIMAGUS_OK);

    /* AEAD: Enc(K, MakeTweak(1, N, AD), 0^128 || M). */
    ASSERT_EQ(animagus_make_tweak(&ctx, tweak, ANIMAGUS_APPLICATION_AEAD,
                                  nonce, sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_OK);
    ASSERT_EQ(animagus_encrypt(&ctx, expected, core_input, sizeof(core_input),
                               tweak), ANIMAGUS_OK);
    ASSERT_EQ(animagus_aead_encrypt(&ctx, actual, message, sizeof(message),
                                    nonce, sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_OK);
    ASSERT_MEMEQ(actual, expected, sizeof(expected));

    /* DAE: Enc(K, MakeTweak(3, empty, empty), 0^128 || M). */
    ASSERT_EQ(animagus_make_tweak(&ctx, tweak, ANIMAGUS_APPLICATION_DAE,
                                  NULL, 0U, NULL, 0U), ANIMAGUS_OK);
    ASSERT_EQ(animagus_encrypt(&ctx, expected, core_input, sizeof(core_input),
                               tweak), ANIMAGUS_OK);
    ASSERT_EQ(animagus_dae_encrypt(&ctx, actual, message, sizeof(message)),
              ANIMAGUS_OK);
    ASSERT_MEMEQ(actual, expected, sizeof(expected));

    /* Tweakable: Enc(K, MakeTweak(2, empty, V), M), via the public form. */
    ASSERT_EQ(animagus_derive_tweak(&ctx, tweak, context, sizeof(context)),
              ANIMAGUS_OK);
    ASSERT_EQ(animagus_encrypt(&ctx, expected, message, sizeof(message),
                               tweak), ANIMAGUS_OK);
    ASSERT_EQ(animagus_tweakable_encrypt(&ctx, actual, message,
                                         sizeof(message), context,
                                         sizeof(context)), ANIMAGUS_OK);
    ASSERT_MEMEQ(actual, expected, sizeof(message));

    animagus_clear(&ctx);
}

static void check_aead_rejects_tampering(void)
{
    const size_t flip_positions[] = { 0U, 15U, 16U, 31U, 32U, 55U };
    const uint8_t key[16] = { 0 };
    uint8_t nonce[12], ad[5], wrong_nonce[12], wrong_ad[5];
    uint8_t message[40];
    uint8_t ciphertext[sizeof(message) + ANIMAGUS_AUTH_SIZE];
    uint8_t tampered[sizeof(ciphertext)];
    uint8_t recovered[sizeof(message)];
    animagus_ctx ctx;
    size_t index;

    fill_pattern(nonce, sizeof(nonce), 0x11U);
    fill_pattern(ad, sizeof(ad), 0x22U);
    fill_pattern(message, sizeof(message), 0x33U);
    memcpy(wrong_nonce, nonce, sizeof(nonce));
    wrong_nonce[3] ^= 0x01U;
    memcpy(wrong_ad, ad, sizeof(ad));
    wrong_ad[4] ^= 0x80U;

    ASSERT_EQ(animagus_init_ex(&ctx, key, sizeof(key),
                               ANIMAGUS_BACKEND_PORTABLE), ANIMAGUS_OK);
    ASSERT_EQ(animagus_aead_encrypt(&ctx, ciphertext, message,
                                    sizeof(message), nonce, sizeof(nonce),
                                    ad, sizeof(ad)), ANIMAGUS_OK);

    for (index = 0;
         index < sizeof(flip_positions) / sizeof(flip_positions[0]);
         ++index) {
        memcpy(tampered, ciphertext, sizeof(tampered));
        tampered[flip_positions[index]] ^= 0x01U;
        fill_pattern(recovered, sizeof(recovered), 0x44U);
        ASSERT_EQ(animagus_aead_decrypt(&ctx, recovered, tampered,
                                        sizeof(tampered), nonce,
                                        sizeof(nonce), ad, sizeof(ad)),
                  ANIMAGUS_ERR_AUTH);
        ASSERT_TRUE(is_all_zero(recovered, sizeof(recovered)));
    }

    fill_pattern(recovered, sizeof(recovered), 0x44U);
    ASSERT_EQ(animagus_aead_decrypt(&ctx, recovered, ciphertext,
                                    sizeof(ciphertext), wrong_nonce,
                                    sizeof(wrong_nonce), ad, sizeof(ad)),
              ANIMAGUS_ERR_AUTH);
    ASSERT_TRUE(is_all_zero(recovered, sizeof(recovered)));
    fill_pattern(recovered, sizeof(recovered), 0x44U);
    ASSERT_EQ(animagus_aead_decrypt(&ctx, recovered, ciphertext,
                                    sizeof(ciphertext), nonce, sizeof(nonce),
                                    wrong_ad, sizeof(wrong_ad)),
              ANIMAGUS_ERR_AUTH);
    ASSERT_TRUE(is_all_zero(recovered, sizeof(recovered)));
    fill_pattern(recovered, sizeof(recovered), 0x44U);
    ASSERT_EQ(animagus_aead_decrypt(&ctx, recovered, ciphertext,
                                    sizeof(ciphertext), nonce, sizeof(nonce),
                                    ad, sizeof(ad) - 1U), ANIMAGUS_ERR_AUTH);
    ASSERT_TRUE(is_all_zero(recovered, sizeof(recovered)));
    fill_pattern(recovered, sizeof(recovered), 0x44U);
    ASSERT_EQ(animagus_aead_decrypt(&ctx, recovered, ciphertext,
                                    sizeof(ciphertext), nonce,
                                    sizeof(nonce) - 1U, ad, sizeof(ad)),
              ANIMAGUS_ERR_AUTH);
    ASSERT_TRUE(is_all_zero(recovered, sizeof(recovered)));

    /* In-place failure zeroes the message part of the buffer. */
    memcpy(tampered, ciphertext, sizeof(tampered));
    tampered[20] ^= 0x10U;
    ASSERT_EQ(animagus_aead_decrypt(&ctx, tampered + ANIMAGUS_AUTH_SIZE,
                                    tampered, sizeof(tampered), nonce,
                                    sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_ERR_AUTH);
    ASSERT_TRUE(is_all_zero(tampered + ANIMAGUS_AUTH_SIZE, sizeof(message)));

    /* The untampered ciphertext still verifies afterwards. */
    ASSERT_EQ(animagus_aead_decrypt(&ctx, recovered, ciphertext,
                                    sizeof(ciphertext), nonce, sizeof(nonce),
                                    ad, sizeof(ad)), ANIMAGUS_OK);
    ASSERT_MEMEQ(recovered, message, sizeof(message));

    animagus_clear(&ctx);
}

static void check_dae_is_deterministic_and_authenticated(void)
{
    const uint8_t key[24] = { 0 };
    uint8_t message[16], other[16];
    uint8_t first[32], second[32], other_ciphertext[32];
    uint8_t recovered[16];
    animagus_ctx ctx;

    fill_pattern(message, sizeof(message), 0x61U);
    memcpy(other, message, sizeof(other));
    other[15] ^= 0x01U;

    ASSERT_EQ(animagus_init_ex(&ctx, key, sizeof(key),
                               ANIMAGUS_BACKEND_PORTABLE), ANIMAGUS_OK);
    ASSERT_EQ(animagus_dae_encrypt(&ctx, first, message, sizeof(message)),
              ANIMAGUS_OK);
    ASSERT_EQ(animagus_dae_encrypt(&ctx, second, message, sizeof(message)),
              ANIMAGUS_OK);
    ASSERT_MEMEQ(second, first, sizeof(first));
    ASSERT_EQ(animagus_dae_encrypt(&ctx, other_ciphertext, other,
                                   sizeof(other)), ANIMAGUS_OK);
    ASSERT_TRUE(memcmp(other_ciphertext, first, sizeof(first)) != 0);

    first[7] ^= 0x04U;
    fill_pattern(recovered, sizeof(recovered), 0x72U);
    ASSERT_EQ(animagus_dae_decrypt(&ctx, recovered, first, sizeof(first)),
              ANIMAGUS_ERR_AUTH);
    ASSERT_TRUE(is_all_zero(recovered, sizeof(recovered)));
    ASSERT_EQ(animagus_dae_decrypt(&ctx, recovered, second, sizeof(second)),
              ANIMAGUS_OK);
    ASSERT_MEMEQ(recovered, message, sizeof(message));

    animagus_clear(&ctx);
}

static void check_tweakable_context_matters(void)
{
    const uint8_t key[16] = { 0 };
    const uint8_t context_a[3] = { 1, 2, 3 };
    const uint8_t context_b[3] = { 1, 2, 4 };
    uint8_t plaintext[40];
    uint8_t with_a[40], with_b[40], with_empty[40];
    animagus_ctx ctx;

    fill_pattern(plaintext, sizeof(plaintext), 0x81U);
    ASSERT_EQ(animagus_init_ex(&ctx, key, sizeof(key),
                               ANIMAGUS_BACKEND_PORTABLE), ANIMAGUS_OK);
    ASSERT_EQ(animagus_tweakable_encrypt(&ctx, with_a, plaintext,
                                         sizeof(plaintext), context_a,
                                         sizeof(context_a)), ANIMAGUS_OK);
    ASSERT_EQ(animagus_tweakable_encrypt(&ctx, with_b, plaintext,
                                         sizeof(plaintext), context_b,
                                         sizeof(context_b)), ANIMAGUS_OK);
    ASSERT_EQ(animagus_tweakable_encrypt(&ctx, with_empty, plaintext,
                                         sizeof(plaintext), NULL, 0U),
              ANIMAGUS_OK);
    ASSERT_TRUE(memcmp(with_a, with_b, sizeof(with_a)) != 0);
    ASSERT_TRUE(memcmp(with_a, with_empty, sizeof(with_a)) != 0);
    /* Decryption under another context yields no error, only garbage. */
    ASSERT_EQ(animagus_tweakable_decrypt(&ctx, with_b, with_a,
                                         sizeof(with_a), context_b,
                                         sizeof(context_b)), ANIMAGUS_OK);
    ASSERT_TRUE(memcmp(with_b, plaintext, sizeof(plaintext)) != 0);
    animagus_clear(&ctx);
}

static void check_tweakable_validation(void)
{
    const uint8_t key[16] = { 0 };
    const uint8_t context[4] = { 0 };
    uint8_t backing[96];
    uint8_t expected[sizeof(backing)];
    uint8_t out[48];
    animagus_ctx ctx = { { 0 } };

    fill_pattern(backing, sizeof(backing), 0xe1U);
    memcpy(expected, backing, sizeof(expected));
    fill_pattern(out, sizeof(out), 0xf1U);

    ASSERT_EQ(animagus_tweakable_decrypt(&ctx, out, backing, 48U,
                                         context, sizeof(context)),
              ANIMAGUS_ERR_STATE);
    ASSERT_EQ(animagus_init(&ctx, key, sizeof(key)), ANIMAGUS_OK);
    ASSERT_EQ(animagus_tweakable_decrypt(&ctx, out, backing, 48U, NULL, 1U),
              ANIMAGUS_ERR_ARGUMENT);
    ASSERT_EQ(animagus_tweakable_decrypt(&ctx, NULL, backing, 48U,
                                         context, sizeof(context)),
              ANIMAGUS_ERR_ARGUMENT);
    ASSERT_EQ(animagus_tweakable_decrypt(&ctx, out, NULL, 48U,
                                         context, sizeof(context)),
              ANIMAGUS_ERR_ARGUMENT);
    ASSERT_EQ(animagus_tweakable_decrypt(&ctx, out, backing, 31U,
                                         context, sizeof(context)),
              ANIMAGUS_ERR_MESSAGE_SIZE);
    ASSERT_EQ(animagus_tweakable_encrypt(&ctx, out, backing, 31U,
                                         context, sizeof(context)),
              ANIMAGUS_ERR_MESSAGE_SIZE);
    /* Partial overlaps reaching into the tail region. */
    ASSERT_EQ(animagus_tweakable_decrypt(&ctx, backing + 8U, backing, 48U,
                                         context, sizeof(context)),
              ANIMAGUS_ERR_OVERLAP);
    ASSERT_EQ(animagus_tweakable_encrypt(&ctx, backing, backing + 40U, 48U,
                                         context, sizeof(context)),
              ANIMAGUS_ERR_OVERLAP);
    ASSERT_MEMEQ(backing, expected, sizeof(backing));

    /* In place and fully disjoint are accepted and agree. */
    ASSERT_EQ(animagus_tweakable_encrypt(&ctx, out, backing, 48U,
                                         context, sizeof(context)),
              ANIMAGUS_OK);
    ASSERT_EQ(animagus_tweakable_encrypt(&ctx, backing, backing, 48U,
                                         context, sizeof(context)),
              ANIMAGUS_OK);
    ASSERT_MEMEQ(backing, out, sizeof(out));
    ASSERT_EQ(animagus_tweakable_decrypt(&ctx, backing, backing, 48U,
                                         context, sizeof(context)),
              ANIMAGUS_OK);
    ASSERT_MEMEQ(backing, expected, 48U);

    animagus_clear(&ctx);
    ASSERT_EQ(animagus_tweakable_encrypt(&ctx, out, backing, 48U,
                                         context, sizeof(context)),
              ANIMAGUS_ERR_STATE);
}

static void check_authenticated_validation(void)
{
    const uint8_t key[16] = { 0 };
    const uint8_t nonce[12] = { 0 };
    const uint8_t ad[4] = { 0 };
    uint8_t backing[96];
    uint8_t expected[sizeof(backing)];
    uint8_t reference[48];
    uint8_t message[ANIMAGUS_AUTH_MIN_MESSAGE_SIZE];
    uint8_t ciphertext[ANIMAGUS_MIN_MESSAGE_SIZE];
    uint8_t out[ANIMAGUS_MIN_MESSAGE_SIZE];
    animagus_ctx ctx = { { 0 } };

    fill_pattern(message, sizeof(message), 0x91U);
    fill_pattern(ciphertext, sizeof(ciphertext), 0xa1U);
    fill_pattern(out, sizeof(out), 0xb1U);
    memcpy(expected, out, sizeof(out));

    /* Context errors come first. */
    ASSERT_EQ(animagus_aead_encrypt(NULL, out, message, sizeof(message),
                                    nonce, sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_ERR_ARGUMENT);
    ASSERT_EQ(animagus_aead_encrypt(&ctx, out, message, sizeof(message),
                                    nonce, sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_ERR_STATE);
    ASSERT_EQ(animagus_aead_decrypt(&ctx, out, ciphertext, sizeof(ciphertext),
                                    nonce, sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_ERR_STATE);
    ASSERT_EQ(animagus_dae_encrypt(&ctx, out, message, sizeof(message)),
              ANIMAGUS_ERR_STATE);
    ASSERT_EQ(animagus_dae_decrypt(&ctx, out, ciphertext, sizeof(ciphertext)),
              ANIMAGUS_ERR_STATE);
    ASSERT_EQ(animagus_init(&ctx, key, sizeof(key)), ANIMAGUS_OK);

    /* Null buffers. */
    ASSERT_EQ(animagus_aead_encrypt(&ctx, NULL, message, sizeof(message),
                                    nonce, sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_ERR_ARGUMENT);
    ASSERT_EQ(animagus_aead_encrypt(&ctx, out, NULL, sizeof(message),
                                    nonce, sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_ERR_ARGUMENT);
    ASSERT_EQ(animagus_aead_encrypt(&ctx, out, message, sizeof(message),
                                    NULL, sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_ERR_ARGUMENT);
    ASSERT_EQ(animagus_aead_encrypt(&ctx, out, message, sizeof(message),
                                    nonce, sizeof(nonce), NULL, sizeof(ad)),
              ANIMAGUS_ERR_ARGUMENT);
    ASSERT_EQ(animagus_aead_decrypt(&ctx, NULL, ciphertext, sizeof(ciphertext),
                                    nonce, sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_ERR_ARGUMENT);
    ASSERT_EQ(animagus_aead_decrypt(&ctx, out, NULL, sizeof(ciphertext),
                                    nonce, sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_ERR_ARGUMENT);
    ASSERT_EQ(animagus_aead_decrypt(&ctx, out, ciphertext, sizeof(ciphertext),
                                    NULL, sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_ERR_ARGUMENT);
    ASSERT_EQ(animagus_aead_decrypt(&ctx, out, ciphertext, sizeof(ciphertext),
                                    nonce, sizeof(nonce), NULL, sizeof(ad)),
              ANIMAGUS_ERR_ARGUMENT);
    ASSERT_EQ(animagus_dae_encrypt(&ctx, NULL, message, sizeof(message)),
              ANIMAGUS_ERR_ARGUMENT);
    ASSERT_EQ(animagus_dae_decrypt(&ctx, out, NULL, sizeof(ciphertext)),
              ANIMAGUS_ERR_ARGUMENT);

    /* AEAD requires a nonempty nonce. */
    ASSERT_EQ(animagus_aead_encrypt(&ctx, out, message, sizeof(message),
                                    nonce, 0U, ad, sizeof(ad)),
              ANIMAGUS_ERR_ARGUMENT);
    ASSERT_EQ(animagus_aead_decrypt(&ctx, out, ciphertext, sizeof(ciphertext),
                                    NULL, 0U, ad, sizeof(ad)),
              ANIMAGUS_ERR_ARGUMENT);

    /* Lengths: 16 <= message, 32 <= ciphertext. */
    ASSERT_EQ(animagus_aead_encrypt(&ctx, out, message, 15U, nonce,
                                    sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_ERR_MESSAGE_SIZE);
    ASSERT_EQ(animagus_aead_encrypt(&ctx, out, message, 0U, nonce,
                                    sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_ERR_MESSAGE_SIZE);
    ASSERT_EQ(animagus_dae_encrypt(&ctx, out, message, 15U),
              ANIMAGUS_ERR_MESSAGE_SIZE);
    ASSERT_EQ(animagus_aead_decrypt(&ctx, out, ciphertext, 31U, nonce,
                                    sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_ERR_MESSAGE_SIZE);
    ASSERT_EQ(animagus_dae_decrypt(&ctx, out, ciphertext, 0U),
              ANIMAGUS_ERR_MESSAGE_SIZE);
    ASSERT_EQ(animagus_dae_decrypt(&ctx, out, ciphertext, 31U),
              ANIMAGUS_ERR_MESSAGE_SIZE);
#if SIZE_MAX > UINT64_C(4503599627370496)
    ASSERT_EQ(animagus_aead_encrypt(&ctx, out, message,
                                    (size_t)ANIMAGUS_AUTH_MAX_MESSAGE_SIZE +
                                    1U, nonce, sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_ERR_MESSAGE_SIZE);
    ASSERT_EQ(animagus_dae_encrypt(&ctx, out, message,
                                   (size_t)ANIMAGUS_AUTH_MAX_MESSAGE_SIZE +
                                   1U), ANIMAGUS_ERR_MESSAGE_SIZE);
    ASSERT_EQ(animagus_aead_decrypt(&ctx, out, ciphertext,
                                    (size_t)ANIMAGUS_MAX_MESSAGE_SIZE + 1U,
                                    nonce, sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_ERR_MESSAGE_SIZE);
    ASSERT_EQ(animagus_dae_decrypt(&ctx, out, ciphertext,
                                   (size_t)ANIMAGUS_MAX_MESSAGE_SIZE + 1U),
              ANIMAGUS_ERR_MESSAGE_SIZE);
#endif
    ASSERT_EQ(animagus_aead_encrypt(&ctx, out, message, SIZE_MAX, nonce,
                                    sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_ERR_MESSAGE_SIZE);
    ASSERT_EQ(animagus_aead_encrypt(&ctx, out, message, SIZE_MAX - 15U,
                                    nonce, sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_ERR_MESSAGE_SIZE);
    ASSERT_MEMEQ(out, expected, sizeof(out));

    /* Placement: only message == ciphertext + 16 or disjoint, checked over
     * the whole range, including the tail of longer messages. */
    fill_pattern(backing, sizeof(backing), 0xc1U);
    memcpy(expected, backing, sizeof(backing));
    ASSERT_EQ(animagus_aead_encrypt(&ctx, backing, backing, 16U, nonce,
                                    sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_ERR_OVERLAP);
    ASSERT_EQ(animagus_aead_encrypt(&ctx, backing, backing + 15U, 16U, nonce,
                                    sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_ERR_OVERLAP);
    ASSERT_EQ(animagus_aead_encrypt(&ctx, backing, backing + 17U, 16U, nonce,
                                    sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_ERR_OVERLAP);
    ASSERT_EQ(animagus_aead_encrypt(&ctx, backing + 8U, backing, 16U, nonce,
                                    sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_ERR_OVERLAP);
    ASSERT_EQ(animagus_aead_encrypt(&ctx, backing, backing + 40U, 32U, nonce,
                                    sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_ERR_OVERLAP);
    ASSERT_EQ(animagus_aead_encrypt(&ctx, backing + 24U, backing, 32U, nonce,
                                    sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_ERR_OVERLAP);
    ASSERT_EQ(animagus_dae_encrypt(&ctx, backing, backing + 31U, 16U),
              ANIMAGUS_ERR_OVERLAP);
    ASSERT_EQ(animagus_dae_encrypt(&ctx, backing, backing + 40U, 32U),
              ANIMAGUS_ERR_OVERLAP);
    ASSERT_EQ(animagus_aead_decrypt(&ctx, backing, backing, 32U, nonce,
                                    sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_ERR_OVERLAP);
    ASSERT_EQ(animagus_aead_decrypt(&ctx, backing + 1U, backing, 32U, nonce,
                                    sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_ERR_OVERLAP);
    ASSERT_EQ(animagus_aead_decrypt(&ctx, backing + 31U, backing, 32U, nonce,
                                    sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_ERR_OVERLAP);
    ASSERT_EQ(animagus_aead_decrypt(&ctx, backing + 40U, backing, 48U, nonce,
                                    sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_ERR_OVERLAP);
    ASSERT_EQ(animagus_aead_decrypt(&ctx, backing, backing + 24U, 48U, nonce,
                                    sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_ERR_OVERLAP);
    ASSERT_EQ(animagus_dae_decrypt(&ctx, backing, backing + 8U, 32U),
              ANIMAGUS_ERR_OVERLAP);
    ASSERT_EQ(animagus_dae_decrypt(&ctx, backing + 40U, backing, 48U),
              ANIMAGUS_ERR_OVERLAP);
    ASSERT_MEMEQ(backing, expected, sizeof(backing));

    /* Adjacent ranges and the in-place offset are accepted and agree with
     * the fully disjoint computation. */
    ASSERT_EQ(animagus_aead_encrypt(&ctx, reference, expected + 32U, 32U,
                                    nonce, sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_OK);
    ASSERT_EQ(animagus_aead_encrypt(&ctx, backing, backing + 48U, 32U, nonce,
                                    sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_OK);
    ASSERT_EQ(animagus_aead_encrypt(&ctx, backing, expected + 48U, 32U, nonce,
                                    sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_OK);
    memcpy(reference, backing, 48U);
    ASSERT_EQ(animagus_aead_decrypt(&ctx, backing + 48U, backing, 48U, nonce,
                                    sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_OK);
    ASSERT_MEMEQ(backing + 48U, expected + 48U, 32U);
    ASSERT_MEMEQ(backing, reference, 48U);
    ASSERT_EQ(animagus_dae_encrypt(&ctx, backing + 48U, backing + 64U, 16U),
              ANIMAGUS_OK);
    ASSERT_EQ(animagus_dae_decrypt(&ctx, backing + 64U, backing + 48U, 32U),
              ANIMAGUS_OK);
    ASSERT_MEMEQ(backing + 64U, expected + 64U, 16U);

    /* Nonce and associated data may alias the ciphertext buffer on
     * encryption and the message buffer on decryption: both are consumed
     * before any output is written. */
    fill_pattern(backing, sizeof(backing), 0xd1U);
    memcpy(expected, backing, sizeof(backing));
    ASSERT_EQ(animagus_aead_encrypt(&ctx, reference, expected + 16U, 16U,
                                    expected, 4U, expected + 4U, 12U),
              ANIMAGUS_OK);
    ASSERT_EQ(animagus_aead_encrypt(&ctx, backing, backing + 16U, 16U,
                                    backing, 4U, backing + 4U, 12U),
              ANIMAGUS_OK);
    ASSERT_MEMEQ(backing, reference, 32U);
    memcpy(backing + 32U, expected, 16U);
    ASSERT_EQ(animagus_aead_decrypt(&ctx, backing + 32U, backing, 32U,
                                    backing + 32U, 4U, backing + 36U, 12U),
              ANIMAGUS_OK);
    ASSERT_MEMEQ(backing + 32U, expected + 16U, 16U);

    animagus_clear(&ctx);
    ASSERT_EQ(animagus_aead_encrypt(&ctx, out, message, sizeof(message),
                                    nonce, sizeof(nonce), ad, sizeof(ad)),
              ANIMAGUS_ERR_STATE);
}

static void check_backend_equivalence(void)
{
    const struct animagus_aead_testvec *vector = NULL;
    uint8_t *portable_ciphertext;
    uint8_t *hardware_ciphertext;
    uint8_t *hardware_message;
    animagus_ctx portable, hardware;
    size_t index;

    if (!host_has_aes_instructions()) {
        return;
    }
    /* Use the longest AEAD vector so the counter mode runs on hardware. */
    for (index = 0; index < animagus_aes256_aead_tv_count; ++index) {
        if (vector == NULL ||
            animagus_aes256_aead_tv[index].message.len > vector->message.len) {
            vector = &animagus_aes256_aead_tv[index];
        }
    }
    ASSERT_TRUE(vector != NULL);
    ASSERT_TRUE(vector->message.len > 32U);
    portable_ciphertext = malloc(vector->ciphertext.len);
    hardware_ciphertext = malloc(vector->ciphertext.len);
    hardware_message = malloc(vector->message.len);
    ASSERT_TRUE(portable_ciphertext != NULL);
    ASSERT_TRUE(hardware_ciphertext != NULL);
    ASSERT_TRUE(hardware_message != NULL);

    ASSERT_EQ(animagus_init_ex(&portable, vector->key.data, vector->key.len,
                               ANIMAGUS_BACKEND_PORTABLE), ANIMAGUS_OK);
    ASSERT_EQ(animagus_init_ex(&hardware, vector->key.data, vector->key.len,
                               ANIMAGUS_BACKEND_HARDWARE), ANIMAGUS_OK);
    ASSERT_TRUE(memcmp(&portable, &hardware, sizeof(portable)) != 0);
    ASSERT_EQ(animagus_aead_encrypt(&portable, portable_ciphertext,
                                    vector->message.data, vector->message.len,
                                    vector->nonce.data, vector->nonce.len,
                                    vector->ad.data, vector->ad.len),
              ANIMAGUS_OK);
    ASSERT_EQ(animagus_aead_encrypt(&hardware, hardware_ciphertext,
                                    vector->message.data, vector->message.len,
                                    vector->nonce.data, vector->nonce.len,
                                    vector->ad.data, vector->ad.len),
              ANIMAGUS_OK);
    ASSERT_MEMEQ(hardware_ciphertext, portable_ciphertext,
                 vector->ciphertext.len);
    ASSERT_MEMEQ(hardware_ciphertext, vector->ciphertext.data,
                 vector->ciphertext.len);
    ASSERT_EQ(animagus_aead_decrypt(&hardware, hardware_message,
                                    portable_ciphertext, vector->ciphertext.len,
                                    vector->nonce.data, vector->nonce.len,
                                    vector->ad.data, vector->ad.len),
              ANIMAGUS_OK);
    ASSERT_MEMEQ(hardware_message, vector->message.data, vector->message.len);

    animagus_clear(&hardware);
    animagus_clear(&portable);
    free(hardware_message);
    free(hardware_ciphertext);
    free(portable_ciphertext);
}

static void check_constant_time_zero_scan(void)
{
    uint8_t bytes[16] = { 0 };
    size_t index;

    ASSERT_TRUE(animagus_ct_all_zero(bytes, sizeof(bytes)));
    ASSERT_TRUE(animagus_ct_all_zero(bytes, 0U));
    for (index = 0; index < sizeof(bytes); ++index) {
        bytes[index] = 0x80U;
        ASSERT_EQ(animagus_ct_all_zero(bytes, sizeof(bytes)), false);
        bytes[index] = 0x01U;
        ASSERT_EQ(animagus_ct_all_zero(bytes, sizeof(bytes)), false);
        bytes[index] = 0U;
    }
}

int main(void)
{
    check_aead_vectors(animagus_aes128_aead_tv, animagus_aes128_aead_tv_count);
    check_aead_vectors(animagus_aes192_aead_tv, animagus_aes192_aead_tv_count);
    check_aead_vectors(animagus_aes256_aead_tv, animagus_aes256_aead_tv_count);
    check_dae_vectors(animagus_aes128_dae_tv, animagus_aes128_dae_tv_count);
    check_dae_vectors(animagus_aes192_dae_tv, animagus_aes192_dae_tv_count);
    check_dae_vectors(animagus_aes256_dae_tv, animagus_aes256_dae_tv_count);
    check_tweakable_vectors(animagus_aes128_tweakable_tv,
                            animagus_aes128_tweakable_tv_count);
    check_tweakable_vectors(animagus_aes192_tweakable_tv,
                            animagus_aes192_tweakable_tv_count);
    check_tweakable_vectors(animagus_aes256_tweakable_tv,
                            animagus_aes256_tweakable_tv_count);
    check_interfaces_match_core_composition();
    check_aead_rejects_tampering();
    check_dae_is_deterministic_and_authenticated();
    check_tweakable_context_matters();
    check_tweakable_validation();
    check_authenticated_validation();
    check_backend_equivalence();
    check_constant_time_zero_scan();
    return 0;
}
