#include "util.h"

void animagus_secure_zero(void *pointer, size_t length)
{
    volatile u8 *bytes = pointer;

    while (length-- != 0U) {
        *bytes++ = 0;
    }
}

bool animagus_ranges_overlap(const void *a, size_t a_len,
                             const void *b, size_t b_len)
{
    uintptr_t a0 = (uintptr_t)a;
    uintptr_t b0 = (uintptr_t)b;
    uintptr_t a_span;
    uintptr_t b_span;
    uintptr_t a1;
    uintptr_t b1;

    if (a_len == 0U || b_len == 0U) {
        return false;
    }
    if ((uintmax_t)(a_len - 1U) > (uintmax_t)UINTPTR_MAX ||
        (uintmax_t)(b_len - 1U) > (uintmax_t)UINTPTR_MAX) {
        return true;
    }
    a_span = (uintptr_t)(a_len - 1U);
    b_span = (uintptr_t)(b_len - 1U);
    if (a0 > UINTPTR_MAX - a_span || b0 > UINTPTR_MAX - b_span) {
        return true;
    }
    a1 = a0 + a_span;
    b1 = b0 + b_span;
    return a0 <= b1 && b0 <= a1;
}
