#include "animagus.h"
#include "animagus_testvecs.h"
#include "test_common.h"
#include "../src/aes.h"
#include "../src/animagus_internal.h"
#include "../src/util.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define ASSERT_TRUE(condition) ASSERT_EQ((condition), 1)

static void check_encrypt_vector(const struct animagus_testvec *vector)
{
    animagus_ctx ctx;
    uint8_t *actual = malloc(vector->plaintext.len);

    ASSERT_TRUE(actual != NULL);
    ASSERT_EQ(vector->tweak.len, ANIMAGUS_TWEAK_SIZE);
    ASSERT_EQ(animagus_init_ex(&ctx, vector->key.data, vector->key.len,
                               ANIMAGUS_BACKEND_PORTABLE), ANIMAGUS_OK);
    ASSERT_EQ(animagus_encrypt(&ctx, actual, vector->plaintext.data,
                               vector->plaintext.len, vector->tweak.data),
              ANIMAGUS_OK);
    ASSERT_MEMEQ(actual, vector->ciphertext.data, vector->ciphertext.len);
    animagus_clear(&ctx);
    free(actual);
}

static void check_encrypt_vectors(const struct animagus_testvec *vectors,
                                  size_t count)
{
    size_t index;

    for (index = 0; index < count; ++index) {
        check_encrypt_vector(&vectors[index]);
    }
}

static void check_decrypt_vector(const struct animagus_testvec *vector)
{
    animagus_ctx ctx;
    uint8_t *actual = malloc(vector->ciphertext.len);

    ASSERT_TRUE(actual != NULL);
    ASSERT_EQ(animagus_init_ex(&ctx, vector->key.data, vector->key.len,
                               ANIMAGUS_BACKEND_PORTABLE), ANIMAGUS_OK);
    ASSERT_EQ(animagus_decrypt(&ctx, actual, vector->ciphertext.data,
                               vector->ciphertext.len, vector->tweak.data),
              ANIMAGUS_OK);
    ASSERT_MEMEQ(actual, vector->plaintext.data, vector->plaintext.len);
    animagus_clear(&ctx);
    free(actual);
}

static void check_decrypt_vectors(const struct animagus_testvec *vectors,
                                  size_t count)
{
    size_t index;

    for (index = 0; index < count; ++index) {
        check_decrypt_vector(&vectors[index]);
    }
}

static void check_backend_equivalence_vector(
    const struct animagus_testvec *vector)
{
    animagus_ctx portable, hardware;
    uint8_t *portable_ciphertext = malloc(vector->plaintext.len);
    uint8_t *hardware_ciphertext = malloc(vector->plaintext.len);
    uint8_t *portable_recovered = malloc(vector->plaintext.len);
    uint8_t *hardware_recovered = malloc(vector->plaintext.len);

    ASSERT_TRUE(portable_ciphertext != NULL);
    ASSERT_TRUE(hardware_ciphertext != NULL);
    ASSERT_TRUE(portable_recovered != NULL);
    ASSERT_TRUE(hardware_recovered != NULL);
    ASSERT_EQ(animagus_init_ex(&portable, vector->key.data, vector->key.len,
                               ANIMAGUS_BACKEND_PORTABLE), ANIMAGUS_OK);
    ASSERT_EQ(animagus_init_ex(&hardware, vector->key.data, vector->key.len,
                               ANIMAGUS_BACKEND_HARDWARE), ANIMAGUS_OK);

    ASSERT_EQ(animagus_encrypt(&portable, portable_ciphertext,
                               vector->plaintext.data, vector->plaintext.len,
                               vector->tweak.data),
              ANIMAGUS_OK);
    ASSERT_EQ(animagus_encrypt(&hardware, hardware_ciphertext,
                               vector->plaintext.data, vector->plaintext.len,
                               vector->tweak.data),
              ANIMAGUS_OK);
    ASSERT_MEMEQ(hardware_ciphertext, portable_ciphertext,
                 vector->plaintext.len);

    ASSERT_EQ(animagus_decrypt(&portable, portable_recovered,
                               portable_ciphertext, vector->plaintext.len,
                               vector->tweak.data),
              ANIMAGUS_OK);
    ASSERT_EQ(animagus_decrypt(&hardware, hardware_recovered,
                               hardware_ciphertext, vector->plaintext.len,
                               vector->tweak.data),
              ANIMAGUS_OK);
    ASSERT_MEMEQ(portable_recovered, vector->plaintext.data,
                 vector->plaintext.len);
    ASSERT_MEMEQ(hardware_recovered, vector->plaintext.data,
                 vector->plaintext.len);

    animagus_clear(&hardware);
    animagus_clear(&portable);
    free(hardware_recovered);
    free(portable_recovered);
    free(hardware_ciphertext);
    free(portable_ciphertext);
}

static void check_backend_equivalence_vectors(
    const struct animagus_testvec *vectors, size_t count)
{
    size_t index;

    for (index = 0; index < count; ++index) {
        check_backend_equivalence_vector(&vectors[index]);
    }
}

static void check_hardware_backend(void)
{
    const uint8_t key[16] = { 0 };
    animagus_ctx ctx;
    animagus_ctx portable;
    animagus_ctx hardware;

    if (!host_has_aes_instructions()) {
        ASSERT_EQ(animagus_aes_hardware_available(), false);
        ASSERT_EQ(animagus_init_ex(&ctx, key, sizeof(key),
                                   ANIMAGUS_BACKEND_HARDWARE),
                  ANIMAGUS_ERR_BACKEND);
        return;
    }

    ASSERT_EQ(animagus_aes_hardware_available(), true);

    /*
     * A hardware context must record a different backend than a portable
     * one, so equal outputs below come from two different code paths and
     * not from the hardware request silently selecting the portable AES.
     */
    ASSERT_EQ(animagus_init_ex(&portable, key, sizeof(key),
                               ANIMAGUS_BACKEND_PORTABLE), ANIMAGUS_OK);
    ASSERT_EQ(animagus_init_ex(&hardware, key, sizeof(key),
                               ANIMAGUS_BACKEND_HARDWARE), ANIMAGUS_OK);
    ASSERT_TRUE(memcmp(&portable, &hardware, sizeof(portable)) != 0);
    ASSERT_EQ(animagus_init_ex(&ctx, key, sizeof(key),
                               ANIMAGUS_BACKEND_AUTO), ANIMAGUS_OK);
    ASSERT_MEMEQ(&ctx, &hardware, sizeof(ctx));
    animagus_clear(&ctx);
    animagus_clear(&hardware);
    animagus_clear(&portable);

    check_backend_equivalence_vectors(animagus_aes128_tv,
                                      animagus_aes128_tv_count);
    check_backend_equivalence_vectors(animagus_aes192_tv,
                                      animagus_aes192_tv_count);
    check_backend_equivalence_vectors(animagus_aes256_tv,
                                      animagus_aes256_tv_count);
}

static void fill_pattern(uint8_t *bytes, size_t length, uint8_t seed)
{
    size_t index;

    for (index = 0; index < length; ++index) {
        bytes[index] = (uint8_t)(seed + index * 29U);
    }
}

static void check_in_place_length(size_t length)
{
    uint8_t key[32];
    uint8_t tweak[ANIMAGUS_TWEAK_SIZE];
    uint8_t *buffer = malloc(length);
    uint8_t *plaintext = malloc(length);
    uint8_t *reference = malloc(length);
    animagus_ctx ctx;

    ASSERT_TRUE(buffer != NULL);
    ASSERT_TRUE(plaintext != NULL);
    ASSERT_TRUE(reference != NULL);
    fill_pattern(key, sizeof(key), 0x21U);
    fill_pattern(tweak, sizeof(tweak), 0x43U);
    fill_pattern(plaintext, length, 0x65U);
    memcpy(buffer, plaintext, length);

    ASSERT_EQ(animagus_init_ex(&ctx, key, sizeof(key),
                               ANIMAGUS_BACKEND_PORTABLE), ANIMAGUS_OK);
    ASSERT_EQ(animagus_encrypt(&ctx, reference, plaintext, length, tweak),
              ANIMAGUS_OK);
    ASSERT_EQ(animagus_encrypt(&ctx, buffer, buffer, length, tweak),
              ANIMAGUS_OK);
    ASSERT_MEMEQ(buffer, reference, length);
    ASSERT_EQ(animagus_decrypt(&ctx, buffer, buffer, length, tweak),
              ANIMAGUS_OK);
    ASSERT_MEMEQ(buffer, plaintext, length);

    animagus_clear(&ctx);
    free(reference);
    free(plaintext);
    free(buffer);
}

static void check_in_place_boundaries(void)
{
    const size_t lengths[] = { 32U, 33U, 47U, 48U, 49U, 64U, 512U };
    size_t index;

    for (index = 0; index < sizeof(lengths) / sizeof(lengths[0]); ++index) {
        check_in_place_length(lengths[index]);
    }
}

static uint64_t xorshift64(uint64_t *state)
{
    uint64_t value = *state;

    value ^= value << 13U;
    value ^= value >> 7U;
    value ^= value << 17U;
    *state = value;
    return value;
}

static void fill_random(uint8_t *bytes, size_t length, uint64_t *state)
{
    size_t index;

    for (index = 0; index < length; ++index) {
        bytes[index] = (uint8_t)xorshift64(state);
    }
}

static void check_randomized_case(size_t key_len, size_t message_len,
                                  uint64_t *state)
{
    uint8_t key[32];
    uint8_t tweak[ANIMAGUS_TWEAK_SIZE];
    uint8_t changed_tweak[sizeof(tweak)];
    uint8_t *plaintext = malloc(message_len);
    uint8_t *ciphertext = malloc(message_len);
    uint8_t *changed_ciphertext = malloc(message_len);
    uint8_t *recovered = malloc(message_len);
    uint8_t *in_place = malloc(message_len);
    animagus_ctx ctx;

    ASSERT_TRUE(plaintext != NULL);
    ASSERT_TRUE(ciphertext != NULL);
    ASSERT_TRUE(changed_ciphertext != NULL);
    ASSERT_TRUE(recovered != NULL);
    ASSERT_TRUE(in_place != NULL);

    fill_random(key, key_len, state);
    fill_random(plaintext, message_len, state);
    fill_random(tweak, sizeof(tweak), state);
    memcpy(changed_tweak, tweak, sizeof(changed_tweak));
    changed_tweak[xorshift64(state) % sizeof(changed_tweak)] ^=
        (uint8_t)(1U << (xorshift64(state) % 8U));

    ASSERT_EQ(animagus_init_ex(&ctx, key, key_len,
                               ANIMAGUS_BACKEND_PORTABLE), ANIMAGUS_OK);

    ASSERT_EQ(animagus_encrypt(&ctx, ciphertext, plaintext, message_len,
                               tweak), ANIMAGUS_OK);
    ASSERT_EQ(animagus_decrypt(&ctx, recovered, ciphertext, message_len,
                               tweak), ANIMAGUS_OK);
    ASSERT_MEMEQ(recovered, plaintext, message_len);

    memcpy(in_place, plaintext, message_len);
    ASSERT_EQ(animagus_encrypt(&ctx, in_place, in_place, message_len,
                               tweak), ANIMAGUS_OK);
    ASSERT_MEMEQ(in_place, ciphertext, message_len);
    ASSERT_EQ(animagus_decrypt(&ctx, in_place, in_place, message_len,
                               tweak), ANIMAGUS_OK);
    ASSERT_MEMEQ(in_place, plaintext, message_len);

    /* Flipping any single tweak bit must change the ciphertext. */
    ASSERT_EQ(animagus_encrypt(&ctx, changed_ciphertext, plaintext,
                               message_len, changed_tweak),
              ANIMAGUS_OK);
    ASSERT_TRUE(memcmp(changed_ciphertext, ciphertext, message_len) != 0);

    animagus_clear(&ctx);
    free(in_place);
    free(recovered);
    free(changed_ciphertext);
    free(ciphertext);
    free(plaintext);
}

static void check_randomized_round_trips(void)
{
    const size_t key_lengths[] = { 16U, 24U, 32U };
    const size_t extra_lengths[] = { 127U, 128U, 129U,
                                     511U, 512U, 513U };
    uint64_t state = UINT64_C(0xd1b54a32d192ed03);
    size_t key_index;
    size_t message_len;
    size_t extra_index;

    for (key_index = 0;
         key_index < sizeof(key_lengths) / sizeof(key_lengths[0]);
         ++key_index) {
        for (message_len = 32U; message_len <= 80U; ++message_len) {
            check_randomized_case(key_lengths[key_index], message_len,
                                  &state);
        }
        for (extra_index = 0;
             extra_index < sizeof(extra_lengths) / sizeof(extra_lengths[0]);
             ++extra_index) {
            check_randomized_case(key_lengths[key_index],
                                  extra_lengths[extra_index], &state);
        }
    }
}

static void check_head_blocks_depend_on_each_other(void)
{
    /*
     * With an empty tail, F is fixed by (T, P1) and the second branch
     * alone changes. Because J = E_seed(F ^ B) is mixed into both
     * branches, C1 must still change when only P2 changes.
     */
    const uint8_t key[16] = { 0 };
    uint8_t tweak[ANIMAGUS_TWEAK_SIZE];
    uint8_t plaintext[32];
    uint8_t changed[sizeof(plaintext)];
    uint8_t ciphertext[sizeof(plaintext)];
    uint8_t changed_ciphertext[sizeof(plaintext)];
    animagus_ctx ctx;

    fill_pattern(tweak, sizeof(tweak), 0x11U);
    fill_pattern(plaintext, sizeof(plaintext), 0x22U);
    memcpy(changed, plaintext, sizeof(changed));
    changed[16] ^= 0x80U;

    ASSERT_EQ(animagus_init_ex(&ctx, key, sizeof(key),
                               ANIMAGUS_BACKEND_PORTABLE), ANIMAGUS_OK);
    ASSERT_EQ(animagus_encrypt(&ctx, ciphertext, plaintext,
                               sizeof(plaintext), tweak), ANIMAGUS_OK);
    ASSERT_EQ(animagus_encrypt(&ctx, changed_ciphertext, changed,
                               sizeof(changed), tweak), ANIMAGUS_OK);
    ASSERT_TRUE(memcmp(ciphertext, changed_ciphertext, 16U) != 0);
    ASSERT_TRUE(memcmp(ciphertext + 16U, changed_ciphertext + 16U,
                       16U) != 0);
    animagus_clear(&ctx);
}

static void check_key_lengths(void)
{
    const size_t valid_lengths[] = { 16, 24, 32 };
    const size_t invalid_lengths[] = { 0, 15, 17, 23, 25, 33 };
    uint8_t key[33] = { 0 };
    animagus_ctx ctx;
    size_t index;

    for (index = 0; index < sizeof(valid_lengths) / sizeof(valid_lengths[0]);
         ++index) {
        ASSERT_EQ(animagus_init_ex(&ctx, key, valid_lengths[index],
                                   ANIMAGUS_BACKEND_PORTABLE), ANIMAGUS_OK);
        animagus_clear(&ctx);
    }
    for (index = 0;
         index < sizeof(invalid_lengths) / sizeof(invalid_lengths[0]);
         ++index) {
        ASSERT_EQ(animagus_init_ex(&ctx, key, invalid_lengths[index],
                                   ANIMAGUS_BACKEND_PORTABLE),
                  ANIMAGUS_ERR_KEY_SIZE);
    }
}

static void check_initialization_errors_are_atomic(void)
{
    const uint8_t key[32] = { 0 };
    animagus_ctx ctx;
    animagus_ctx expected;

    ASSERT_EQ(animagus_init_ex(NULL, key, 16U, ANIMAGUS_BACKEND_PORTABLE),
              ANIMAGUS_ERR_ARGUMENT);
    ASSERT_EQ(animagus_init_ex(&ctx, NULL, 16U, ANIMAGUS_BACKEND_PORTABLE),
              ANIMAGUS_ERR_ARGUMENT);

    ASSERT_EQ(animagus_init(&ctx, key, 16U), ANIMAGUS_OK);
    memcpy(&expected, &ctx, sizeof(expected));

    ASSERT_EQ(animagus_init_ex(&ctx, key, 15U, ANIMAGUS_BACKEND_PORTABLE),
              ANIMAGUS_ERR_KEY_SIZE);
    ASSERT_MEMEQ(&ctx, &expected, sizeof(ctx));
    if (!host_has_aes_instructions()) {
        ASSERT_EQ(animagus_init_ex(&ctx, key, 16U,
                                   ANIMAGUS_BACKEND_HARDWARE),
                  ANIMAGUS_ERR_BACKEND);
        ASSERT_MEMEQ(&ctx, &expected, sizeof(ctx));
    }
    ASSERT_EQ(animagus_init_ex(&ctx, key, 16U,
                               (enum animagus_backend)99),
              ANIMAGUS_ERR_ARGUMENT);
    ASSERT_MEMEQ(&ctx, &expected, sizeof(ctx));
    ASSERT_EQ(animagus_init_ex(&ctx, key, 16U, ANIMAGUS_BACKEND_AUTO),
              ANIMAGUS_OK);
    animagus_clear(&ctx);
}

static void check_clear(void)
{
    const uint8_t key[16] = { 0 };
    const animagus_ctx zero = { { 0 } };
    animagus_ctx ctx;

    animagus_clear(NULL);
    ASSERT_EQ(animagus_init(&ctx, key, sizeof(key)), ANIMAGUS_OK);
    animagus_clear(&ctx);
    ASSERT_MEMEQ(&ctx, &zero, sizeof(ctx));
}

typedef int (*animagus_operation)(const animagus_ctx *, uint8_t *,
                                  const uint8_t *, size_t,
                                  const uint8_t *);

static void assert_operation_error_preserves_destination(
    animagus_operation operation, const animagus_ctx *ctx,
    const uint8_t *src, size_t len, const uint8_t *tweak,
    int expected_status)
{
    const uint8_t expected[32] = {
        0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
        0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
        0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
        0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
    };
    uint8_t destination[32];

    memcpy(destination, expected, sizeof(destination));
    ASSERT_EQ(operation(ctx, destination, src, len, tweak),
              expected_status);
    ASSERT_MEMEQ(destination, expected, sizeof(destination));
}

static void check_operation_validation(animagus_operation operation)
{
    const uint8_t key[16] = { 0 };
    const uint8_t source[32] = { 0 };
    const uint8_t tweak[ANIMAGUS_TWEAK_SIZE] = { 0 };
    animagus_ctx ctx = { { 0 } };

    assert_operation_error_preserves_destination(
        operation, NULL, source, sizeof(source), tweak,
        ANIMAGUS_ERR_ARGUMENT);
    assert_operation_error_preserves_destination(
        operation, &ctx, source, sizeof(source), tweak,
        ANIMAGUS_ERR_STATE);

    ASSERT_EQ(animagus_init(&ctx, key, sizeof(key)), ANIMAGUS_OK);
    ASSERT_EQ(operation(&ctx, NULL, source, sizeof(source), tweak),
              ANIMAGUS_ERR_ARGUMENT);
    assert_operation_error_preserves_destination(
        operation, &ctx, NULL, sizeof(source), tweak,
        ANIMAGUS_ERR_ARGUMENT);
    assert_operation_error_preserves_destination(
        operation, &ctx, source, sizeof(source), NULL,
        ANIMAGUS_ERR_ARGUMENT);
    assert_operation_error_preserves_destination(
        operation, &ctx, source, 31U, tweak,
        ANIMAGUS_ERR_MESSAGE_SIZE);
    assert_operation_error_preserves_destination(
        operation, &ctx, source, 0U, tweak,
        ANIMAGUS_ERR_MESSAGE_SIZE);
#if SIZE_MAX > UINT64_C(4503599627370496)
    assert_operation_error_preserves_destination(
        operation, &ctx, source,
        (size_t)ANIMAGUS_MAX_MESSAGE_SIZE + 1U, tweak,
        ANIMAGUS_ERR_MESSAGE_SIZE);
#endif
#if SIZE_MAX > UINT64_MAX
    assert_operation_error_preserves_destination(
        operation, &ctx, source, (size_t)UINT64_MAX + 33U, tweak,
        ANIMAGUS_ERR_MESSAGE_SIZE);
#endif

    animagus_clear(&ctx);
    assert_operation_error_preserves_destination(
        operation, &ctx, source, sizeof(source), tweak,
        ANIMAGUS_ERR_STATE);
}

static void assert_overlap_error_preserves_backing(
    animagus_operation operation, animagus_ctx *ctx, size_t len,
    size_t destination_offset, size_t source_offset,
    size_t tweak_offset)
{
    uint8_t backing[128];
    uint8_t expected[sizeof(backing)];
    size_t index;

    for (index = 0; index < sizeof(backing); ++index) {
        backing[index] = (uint8_t)(index * 3U + 1U);
    }
    memcpy(expected, backing, sizeof(expected));

    ASSERT_EQ(operation(ctx, backing + destination_offset,
                        backing + source_offset, len,
                        backing + tweak_offset),
              ANIMAGUS_ERR_OVERLAP);
    ASSERT_MEMEQ(backing, expected, sizeof(backing));
}

static void check_overlap_validation(animagus_operation operation)
{
    const uint8_t key[16] = { 0 };
    animagus_ctx ctx;

    ASSERT_EQ(animagus_init_ex(&ctx, key, sizeof(key),
                               ANIMAGUS_BACKEND_PORTABLE), ANIMAGUS_OK);

    /* Partial source/destination overlap in both directions at the
     * minimum length; the tweak sits in a disjoint region. */
    assert_overlap_error_preserves_backing(operation, &ctx, 32U,
                                           17U, 16U, 64U);
    assert_overlap_error_preserves_backing(operation, &ctx, 32U,
                                           16U, 17U, 64U);

    /* Destination/tweak overlap at both edges and by containment. */
    assert_overlap_error_preserves_backing(operation, &ctx, 32U,
                                           48U, 0U, 48U);
    assert_overlap_error_preserves_backing(operation, &ctx, 32U,
                                           48U, 0U, 64U);
    assert_overlap_error_preserves_backing(operation, &ctx, 32U,
                                           48U, 0U, 79U);
    assert_overlap_error_preserves_backing(operation, &ctx, 32U,
                                           48U, 0U, 33U);
    assert_overlap_error_preserves_backing(operation, &ctx, 32U,
                                           48U, 0U, 40U);
    assert_overlap_error_preserves_backing(operation, &ctx, 32U,
                                           48U, 0U, 72U);

    /* In place with the tweak inside the buffer is also an overlap. */
    assert_overlap_error_preserves_backing(operation, &ctx, 32U,
                                           32U, 32U, 40U);

    /* Overlaps that touch only the tail region of a longer message: the
     * check must cover all len bytes, not just the two head blocks. */
    assert_overlap_error_preserves_backing(operation, &ctx, 48U,
                                           40U, 0U, 96U);
    assert_overlap_error_preserves_backing(operation, &ctx, 48U,
                                           0U, 40U, 96U);
    assert_overlap_error_preserves_backing(operation, &ctx, 64U,
                                           32U, 0U, 100U);
    assert_overlap_error_preserves_backing(operation, &ctx, 48U,
                                           0U, 48U, 40U);
    assert_overlap_error_preserves_backing(operation, &ctx, 64U,
                                           0U, 64U, 50U);

    animagus_clear(&ctx);
}

static void check_allowed_buffer_relationships(animagus_operation operation)
{
    const uint8_t key[16] = { 0 };
    uint8_t backing[96];
    uint8_t source[32];
    uint8_t tweak[ANIMAGUS_TWEAK_SIZE];
    uint8_t reference[32];
    animagus_ctx ctx;

    ASSERT_EQ(animagus_init_ex(&ctx, key, sizeof(key),
                               ANIMAGUS_BACKEND_PORTABLE), ANIMAGUS_OK);

    /* Adjacent destination, source, and tweak ranges do not overlap, and
     * the result equals the fully disjoint computation. */
    fill_pattern(backing, sizeof(backing), 0x37U);
    memcpy(source, backing + 32U, sizeof(source));
    memcpy(tweak, backing + 64U, sizeof(tweak));
    ASSERT_EQ(operation(&ctx, reference, source, sizeof(source), tweak),
              ANIMAGUS_OK);
    ASSERT_EQ(operation(&ctx, backing, backing + 32U, 32U, backing + 64U),
              ANIMAGUS_OK);
    ASSERT_MEMEQ(backing, reference, sizeof(reference));
    ASSERT_MEMEQ(backing + 32U, source, sizeof(source));

    fill_pattern(backing, sizeof(backing), 0x37U);
    memcpy(source, backing, sizeof(source));
    memcpy(tweak, backing + 16U, sizeof(tweak));
    ASSERT_EQ(operation(&ctx, reference, source, sizeof(source), tweak),
              ANIMAGUS_OK);
    ASSERT_EQ(operation(&ctx, backing + 32U, backing, 32U, backing + 16U),
              ANIMAGUS_OK);
    ASSERT_MEMEQ(backing + 32U, reference, sizeof(reference));

    /* A tweak may overlap the source when the destination is disjoint. */
    fill_pattern(backing, sizeof(backing), 0x59U);
    memcpy(source, backing, sizeof(source));
    memcpy(tweak, backing + 3U, sizeof(tweak));
    ASSERT_EQ(operation(&ctx, reference, source, sizeof(source), tweak),
              ANIMAGUS_OK);
    ASSERT_EQ(operation(&ctx, backing + 32U, backing, 32U, backing + 3U),
              ANIMAGUS_OK);
    ASSERT_MEMEQ(backing + 32U, reference, sizeof(reference));
    ASSERT_MEMEQ(backing, source, sizeof(source));

    animagus_clear(&ctx);
}

static void check_make_tweak_vector(
    const struct animagus_tweak_testvec *vector)
{
    uint8_t derived[ANIMAGUS_TWEAK_SIZE];
    uint8_t public_form[ANIMAGUS_TWEAK_SIZE];
    uint8_t plaintext[48];
    uint8_t ciphertext[sizeof(plaintext)];
    uint8_t recovered[sizeof(plaintext)];
    animagus_ctx ctx;

    ASSERT_EQ(animagus_init_ex(&ctx, vector->key.data, vector->key.len,
                               ANIMAGUS_BACKEND_PORTABLE), ANIMAGUS_OK);
    ASSERT_EQ(animagus_make_tweak(
                  &ctx, derived,
                  (enum animagus_application)vector->application,
                  vector->nonce.data, vector->nonce.len,
                  vector->ad.data, vector->ad.len), ANIMAGUS_OK);
    ASSERT_EQ(vector->tweak.len, sizeof(derived));
    ASSERT_MEMEQ(derived, vector->tweak.data, sizeof(derived));

    /* The public derivation is the tweakable form with the context in the
     * associated-data position. */
    if (vector->application == ANIMAGUS_APPLICATION_TWEAKABLE) {
        ASSERT_EQ(vector->nonce.len, 0U);
        ASSERT_EQ(animagus_derive_tweak(&ctx, public_form, vector->ad.data,
                                        vector->ad.len), ANIMAGUS_OK);
        ASSERT_MEMEQ(public_form, vector->tweak.data, sizeof(public_form));
    }

    fill_pattern(plaintext, sizeof(plaintext), 0x2bU);
    ASSERT_EQ(animagus_encrypt(&ctx, ciphertext, plaintext,
                               sizeof(plaintext), derived), ANIMAGUS_OK);
    ASSERT_EQ(animagus_decrypt(&ctx, recovered, ciphertext,
                               sizeof(ciphertext), derived), ANIMAGUS_OK);
    ASSERT_MEMEQ(recovered, plaintext, sizeof(plaintext));
    animagus_clear(&ctx);
}

static void check_make_tweak_vectors(
    const struct animagus_tweak_testvec *vectors, size_t count)
{
    size_t index;
    size_t tweakable_cases = 0;

    for (index = 0; index < count; ++index) {
        check_make_tweak_vector(&vectors[index]);
        if (vectors[index].application == ANIMAGUS_APPLICATION_TWEAKABLE) {
            ++tweakable_cases;
        }
    }
    ASSERT_TRUE(tweakable_cases > 0U);
}

static void check_make_tweak_shapes(void)
{
    const uint8_t key[16] = { 0 };
    const uint8_t nonce[12] = { 0 };
    const uint8_t ad[4] = { 0 };
    uint8_t derived[ANIMAGUS_TWEAK_SIZE];
    uint8_t repeated[ANIMAGUS_TWEAK_SIZE];
    animagus_ctx ctx;

    ASSERT_EQ(animagus_init_ex(&ctx, key, sizeof(key),
                               ANIMAGUS_BACKEND_PORTABLE), ANIMAGUS_OK);

    /* AEAD needs a nonce, the others carry none, and DAE carries no
     * context either. Unknown identifiers are rejected. */
    ASSERT_EQ(animagus_make_tweak(&ctx, derived, ANIMAGUS_APPLICATION_AEAD,
                                  NULL, 0U, ad, sizeof(ad)),
              ANIMAGUS_ERR_ARGUMENT);
    ASSERT_EQ(animagus_make_tweak(&ctx, derived,
                                  ANIMAGUS_APPLICATION_TWEAKABLE,
                                  nonce, sizeof(nonce), NULL, 0U),
              ANIMAGUS_ERR_ARGUMENT);
    ASSERT_EQ(animagus_make_tweak(&ctx, derived, ANIMAGUS_APPLICATION_DAE,
                                  NULL, 0U, ad, sizeof(ad)),
              ANIMAGUS_ERR_ARGUMENT);
    ASSERT_EQ(animagus_make_tweak(&ctx, derived,
                                  (enum animagus_application)0,
                                  nonce, sizeof(nonce), NULL, 0U),
              ANIMAGUS_ERR_ARGUMENT);
    ASSERT_EQ(animagus_make_tweak(&ctx, derived,
                                  (enum animagus_application)4,
                                  nonce, sizeof(nonce), NULL, 0U),
              ANIMAGUS_ERR_ARGUMENT);
    ASSERT_EQ(animagus_make_tweak(&ctx, derived, ANIMAGUS_APPLICATION_AEAD,
                                  NULL, sizeof(nonce), NULL, 0U),
              ANIMAGUS_ERR_ARGUMENT);
    ASSERT_EQ(animagus_make_tweak(&ctx, derived, ANIMAGUS_APPLICATION_AEAD,
                                  nonce, sizeof(nonce), NULL, 3U),
              ANIMAGUS_ERR_ARGUMENT);
#if SIZE_MAX > UINT64_C(2305843009213693951)
    ASSERT_EQ(animagus_make_tweak(&ctx, derived, ANIMAGUS_APPLICATION_AEAD,
                                  nonce,
                                  (size_t)ANIMAGUS_MAX_FRAMED_SIZE + 1U,
                                  NULL, 0U),
              ANIMAGUS_ERR_ARGUMENT);
#endif

    /* Valid shapes are deterministic and separated by the identifier. */
    ASSERT_EQ(animagus_make_tweak(&ctx, derived, ANIMAGUS_APPLICATION_AEAD,
                                  nonce, 1U, NULL, 0U), ANIMAGUS_OK);
    ASSERT_EQ(animagus_make_tweak(&ctx, derived,
                                  ANIMAGUS_APPLICATION_TWEAKABLE,
                                  NULL, 0U, NULL, 0U), ANIMAGUS_OK);
    ASSERT_EQ(animagus_make_tweak(&ctx, repeated, ANIMAGUS_APPLICATION_DAE,
                                  NULL, 0U, NULL, 0U), ANIMAGUS_OK);
    ASSERT_TRUE(memcmp(repeated, derived, sizeof(derived)) != 0);
    ASSERT_EQ(animagus_make_tweak(&ctx, derived, ANIMAGUS_APPLICATION_DAE,
                                  NULL, 0U, NULL, 0U), ANIMAGUS_OK);
    ASSERT_MEMEQ(derived, repeated, sizeof(derived));

    animagus_clear(&ctx);
}

static void check_derive_tweak_validation(void)
{
    const uint8_t key[16] = { 0 };
    const uint8_t context[12] = { 0 };
    uint8_t derived[ANIMAGUS_TWEAK_SIZE];
    uint8_t repeated[ANIMAGUS_TWEAK_SIZE];
    uint8_t other[ANIMAGUS_TWEAK_SIZE];
    animagus_ctx ctx = { { 0 } };

    ASSERT_EQ(animagus_derive_tweak(NULL, derived, context, sizeof(context)),
              ANIMAGUS_ERR_ARGUMENT);
    ASSERT_EQ(animagus_derive_tweak(&ctx, derived, context, sizeof(context)),
              ANIMAGUS_ERR_STATE);

    ASSERT_EQ(animagus_init(&ctx, key, sizeof(key)), ANIMAGUS_OK);
    ASSERT_EQ(animagus_derive_tweak(&ctx, NULL, context, sizeof(context)),
              ANIMAGUS_ERR_ARGUMENT);
    ASSERT_EQ(animagus_derive_tweak(&ctx, derived, NULL, 3U),
              ANIMAGUS_ERR_ARGUMENT);
#if SIZE_MAX > UINT64_C(2305843009213693951)
    ASSERT_EQ(animagus_derive_tweak(&ctx, derived, context,
                                    (size_t)ANIMAGUS_MAX_FRAMED_SIZE + 1U),
              ANIMAGUS_ERR_ARGUMENT);
#endif

    /* Empty and nonempty contexts are valid, deterministic, and differ. */
    ASSERT_EQ(animagus_derive_tweak(&ctx, derived, NULL, 0U), ANIMAGUS_OK);
    ASSERT_EQ(animagus_derive_tweak(&ctx, repeated, context, 0U),
              ANIMAGUS_OK);
    ASSERT_MEMEQ(repeated, derived, sizeof(derived));
    ASSERT_EQ(animagus_derive_tweak(&ctx, other, context, sizeof(context)),
              ANIMAGUS_OK);
    ASSERT_TRUE(memcmp(other, derived, sizeof(derived)) != 0);

    /* The public form is exactly the internal tweakable form. */
    ASSERT_EQ(animagus_make_tweak(&ctx, repeated,
                                  ANIMAGUS_APPLICATION_TWEAKABLE, NULL, 0U,
                                  context, sizeof(context)), ANIMAGUS_OK);
    ASSERT_MEMEQ(repeated, other, sizeof(other));

    animagus_clear(&ctx);
    ASSERT_EQ(animagus_derive_tweak(&ctx, derived, context, sizeof(context)),
              ANIMAGUS_ERR_STATE);
}

static void check_derive_tweak_output_may_overlap_input(void)
{
    const uint8_t key[16] = { 0 };
    uint8_t buffer[ANIMAGUS_TWEAK_SIZE + 8U];
    uint8_t expected[ANIMAGUS_TWEAK_SIZE];
    animagus_ctx ctx;

    fill_pattern(buffer, sizeof(buffer), 0x71U);
    ASSERT_EQ(animagus_init_ex(&ctx, key, sizeof(key),
                               ANIMAGUS_BACKEND_PORTABLE), ANIMAGUS_OK);
    ASSERT_EQ(animagus_derive_tweak(&ctx, expected, buffer, sizeof(buffer)),
              ANIMAGUS_OK);
    ASSERT_EQ(animagus_derive_tweak(&ctx, buffer, buffer, sizeof(buffer)),
              ANIMAGUS_OK);
    ASSERT_MEMEQ(buffer, expected, sizeof(expected));
    animagus_clear(&ctx);
}

static void check_range_overlap_utility(void)
{
    uint8_t bytes[8] = { 0 };
    const void *near_end = (const void *)(uintptr_t)(UINTPTR_MAX - 1U);

    ASSERT_EQ(animagus_ranges_overlap(bytes, 0U, bytes, sizeof(bytes)), 0);
    ASSERT_EQ(animagus_ranges_overlap(bytes, 4U, bytes + 4U, 4U), 0);
    ASSERT_TRUE(animagus_ranges_overlap(bytes, 4U, bytes + 3U, 1U));
    ASSERT_TRUE(animagus_ranges_overlap(bytes + 2U, 2U,
                                        bytes, sizeof(bytes)));
    ASSERT_TRUE(animagus_ranges_overlap(near_end, 3U, bytes, 1U));
    ASSERT_EQ(animagus_size_exceeds(32U, UINT64_C(32)), false);
    ASSERT_TRUE(animagus_size_exceeds(33U, UINT64_C(32)));
    ASSERT_EQ(animagus_size_exceeds(SIZE_MAX, UINT64_MAX), false);
}

int main(void)
{
    check_encrypt_vectors(animagus_aes128_tv, animagus_aes128_tv_count);
    check_encrypt_vectors(animagus_aes192_tv, animagus_aes192_tv_count);
    check_encrypt_vectors(animagus_aes256_tv, animagus_aes256_tv_count);
    check_decrypt_vectors(animagus_aes128_tv, animagus_aes128_tv_count);
    check_decrypt_vectors(animagus_aes192_tv, animagus_aes192_tv_count);
    check_decrypt_vectors(animagus_aes256_tv, animagus_aes256_tv_count);
    check_hardware_backend();
    check_in_place_boundaries();
    check_randomized_round_trips();
    check_head_blocks_depend_on_each_other();
    check_key_lengths();
    check_initialization_errors_are_atomic();
    check_clear();
    check_operation_validation(animagus_encrypt);
    check_operation_validation(animagus_decrypt);
    check_overlap_validation(animagus_encrypt);
    check_overlap_validation(animagus_decrypt);
    check_allowed_buffer_relationships(animagus_encrypt);
    check_allowed_buffer_relationships(animagus_decrypt);
    check_make_tweak_vectors(animagus_aes128_tweak_tv,
                             animagus_aes128_tweak_tv_count);
    check_make_tweak_vectors(animagus_aes192_tweak_tv,
                             animagus_aes192_tweak_tv_count);
    check_make_tweak_vectors(animagus_aes256_tweak_tv,
                             animagus_aes256_tweak_tv_count);
    check_make_tweak_shapes();
    check_derive_tweak_validation();
    check_derive_tweak_output_may_overlap_input();
    check_range_overlap_utility();
    return 0;
}
