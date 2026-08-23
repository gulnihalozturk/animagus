#pragma once

#include <stdbool.h>
#include <stddef.h>

void assert_eq_size_t(size_t actual, size_t expected, const char *actual_expr,
                      const char *expected_expr, const char *file, int line);
void assert_memeq(const void *actual, const void *expected, size_t length,
                  const char *actual_expr, const char *expected_expr,
                  const char *file, int line);
size_t hex_decode(unsigned char *out, size_t out_size, const char *hex);
bool host_has_aes_instructions(void);

#define ASSERT_EQ(actual, expected) \
    assert_eq_size_t((actual), (expected), #actual, #expected, __FILE__, __LINE__)

#define ASSERT_MEMEQ(actual, expected, length) \
    assert_memeq((actual), (expected), (length), #actual, #expected, __FILE__, __LINE__)
