/*
 * Cryptographic benchmark timing helpers.
 *
 * Portions of the benchmark structure and reporting format are adapted from
 * Google's cipherbench, Copyright 2018 Google LLC, under the MIT License.
 * https://opensource.org/licenses/MIT
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

int bench_now_ns(uint64_t *nanoseconds);
uint64_t bench_kb_per_second(size_t bytes, uint64_t nanoseconds);
int bench_read_max_frequency_khz(uint64_t *frequency_khz);
long double bench_cycles_per_byte(size_t bytes, uint64_t nanoseconds,
                                  uint64_t frequency_khz);
