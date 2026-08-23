/*
 * Reusable timing loop for the Animagus cipher benchmark.
 *
 * Adapted from Google's cipher benchmark template, Copyright 2018 Google
 * LLC, under the MIT License.  The public Animagus operation is supplied as
 * a macro argument so the timed loop calls it directly.  On failure the
 * macro assigns the caller's int status lvalue and jumps to the caller's
 * `out` label; the elapsed-time lvalue is never used for status values.
 * https://opensource.org/licenses/MIT
 */
#pragma once

#include "bench_time.h"

#include <stdint.h>

#define CIPHER_BENCHMARK_MEASURE(elapsed_ns, status, operation, context,    \
                                 destination, source, length, tweak_bytes,  \
                                 tweak_length, messages, trial_count)       \
    do {                                                                     \
        size_t benchmark_try;                                                \
        (elapsed_ns) = UINT64_MAX;                                           \
        for (benchmark_try = 0U;                                          \
             benchmark_try < (trial_count); ++benchmark_try) {             \
            size_t message_index;                                            \
            uint64_t benchmark_start;                                        \
            uint64_t benchmark_end;                                          \
            if (bench_now_ns(&benchmark_start) != 0) {                       \
                (status) = fail_errno("clock_gettime");                      \
                goto out;                                                    \
            }                                                                \
            for (message_index = 0U; message_index < (messages);             \
                 ++message_index) {                                          \
                if ((operation)((context), (destination), (source),          \
                                (length), (tweak_bytes),                     \
                                (tweak_length)) != ANIMAGUS_OK) {            \
                    (status) = fail_message("Animagus operation failed");    \
                    goto out;                                                \
                }                                                            \
            }                                                                \
            if (bench_now_ns(&benchmark_end) != 0) {                         \
                (status) = fail_errno("clock_gettime");                      \
                goto out;                                                    \
            }                                                                \
            if (benchmark_end < benchmark_start) {                           \
                (status) = fail_message("monotonic clock moved backwards");  \
                goto out;                                                    \
            }                                                                \
            if (benchmark_end - benchmark_start < (elapsed_ns)) {            \
                (elapsed_ns) = benchmark_end - benchmark_start;              \
            }                                                                \
        }                                                                    \
    } while (0)
