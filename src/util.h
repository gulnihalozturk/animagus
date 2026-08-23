#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#define __cacheline_aligned __attribute__((aligned(64)))
#define asmlinkage

static __always_inline u32 ror32(u32 word, unsigned int shift)
{
    return (word >> shift) | (word << (32U - shift));
}

static __always_inline u32 get_unaligned_le32(const void *pointer)
{
    const u8 *bytes = pointer;

    return (u32)bytes[0] | ((u32)bytes[1] << 8U) |
           ((u32)bytes[2] << 16U) | ((u32)bytes[3] << 24U);
}

static __always_inline void put_unaligned_le32(u32 value, void *pointer)
{
    u8 *bytes = pointer;

    bytes[0] = (u8)value;
    bytes[1] = (u8)(value >> 8U);
    bytes[2] = (u8)(value >> 16U);
    bytes[3] = (u8)(value >> 24U);
}

void animagus_secure_zero(void *pointer, size_t length);
bool animagus_ranges_overlap(const void *a, size_t a_len,
                             const void *b, size_t b_len);
