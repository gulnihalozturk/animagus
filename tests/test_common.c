#include "test_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#include <cpuid.h>
#elif defined(__aarch64__) && (defined(__linux__) || defined(__ANDROID__))
#include <asm/hwcap.h>
#include <sys/auxv.h>
#endif

static void assertion_failed(const char *file, int line, const char *message)
{
    (void)fprintf(stderr, "%s:%d: assertion failed: %s\n", file, line, message);
    abort();
}

void assert_eq_size_t(size_t actual, size_t expected, const char *actual_expr,
                      const char *expected_expr, const char *file, int line)
{
    if (actual != expected) {
        (void)fprintf(stderr, "%s:%d: assertion failed: %s == %s "
                "(got %zu, expected %zu)\n", file, line, actual_expr,
                expected_expr, actual, expected);
        abort();
    }
}

void assert_memeq(const void *actual, const void *expected, size_t length,
                  const char *actual_expr, const char *expected_expr,
                  const char *file, int line)
{
    if (memcmp(actual, expected, length) != 0) {
        char message[256];
        (void)snprintf(message, sizeof(message), "%s equals %s", actual_expr,
                       expected_expr);
        assertion_failed(file, line, message);
    }
}

static unsigned int hex_value(char character)
{
    if (character >= '0' && character <= '9') {
        return (unsigned int)(character - '0');
    }
    if (character >= 'a' && character <= 'f') {
        return (unsigned int)(character - 'a' + 10);
    }
    if (character >= 'A' && character <= 'F') {
        return (unsigned int)(character - 'A' + 10);
    }
    assertion_failed(__FILE__, __LINE__, "invalid hexadecimal character");
    return 0;
}

size_t hex_decode(unsigned char *out, size_t out_size, const char *hex)
{
    size_t hex_length = strlen(hex);
    size_t output_length;
    size_t index;

    if ((hex_length & 1U) != 0U) {
        assertion_failed(__FILE__, __LINE__, "hexadecimal input has odd length");
    }
    output_length = hex_length / 2U;
    if (output_length > out_size) {
        assertion_failed(__FILE__, __LINE__, "hexadecimal output is too large");
    }
    for (index = 0; index < output_length; ++index) {
        out[index] = (unsigned char)((hex_value(hex[2U * index]) << 4U) |
                                     hex_value(hex[2U * index + 1U]));
    }
    return output_length;
}

bool host_has_aes_instructions(void)
{
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
    unsigned int eax, ebx, ecx, edx;

    return __get_cpuid(1U, &eax, &ebx, &ecx, &edx) != 0 &&
           (ecx & bit_AES) != 0U;
#elif defined(__aarch64__) && (defined(__linux__) || defined(__ANDROID__))
    return (getauxval(AT_HWCAP) & HWCAP_AES) != 0UL;
#else
    return false;
#endif
}
