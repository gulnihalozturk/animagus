/*
 * Cryptographic benchmark timing helpers.
 *
 * Portions of the benchmark structure and reporting format are adapted from
 * Google's cipherbench, Copyright 2018 Google LLC, under the MIT License.
 * https://opensource.org/licenses/MIT
 */
#define _POSIX_C_SOURCE 200809L

#include "bench_time.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int bench_now_ns(uint64_t *nanoseconds)
{
    struct timespec timestamp;

    if (clock_gettime(CLOCK_MONOTONIC, &timestamp) != 0) {
        return -1;
    }
    *nanoseconds = (uint64_t)timestamp.tv_sec * UINT64_C(1000000000) +
                   (uint64_t)timestamp.tv_nsec;
    return 0;
}

uint64_t bench_kb_per_second(size_t bytes, uint64_t nanoseconds)
{
    long double throughput;

    if (nanoseconds == 0U) {
        return 0U;
    }
    throughput = ((long double)bytes * 1000000.0L) /
                 (long double)nanoseconds;
    if (throughput >= (long double)UINT64_MAX) {
        return UINT64_MAX;
    }
    return (uint64_t)throughput;
}

int bench_read_max_frequency_khz(uint64_t *frequency_khz)
{
    static const char path[] =
        "/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq";
    char contents[64];
    char *end;
    FILE *file;
    unsigned long long value;

    *frequency_khz = 0U;
    file = fopen(path, "r");
    if (file == NULL) {
        return -1;
    }
    if (fgets(contents, sizeof(contents), file) == NULL) {
        fclose(file);
        return -1;
    }
    if (fclose(file) != 0) {
        return -1;
    }
    errno = 0;
    value = strtoull(contents, &end, 10);
    if (errno != 0 || end == contents || value == 0U) {
        return -1;
    }
    while (*end == ' ' || *end == '\t' || *end == '\n') {
        ++end;
    }
    if (*end != '\0' || value > UINT64_MAX) {
        return -1;
    }
    *frequency_khz = (uint64_t)value;
    return 0;
}

long double bench_cycles_per_byte(size_t bytes, uint64_t nanoseconds,
                                  uint64_t frequency_khz)
{
    if (bytes == 0U || nanoseconds == 0U || frequency_khz == 0U) {
        return 0.0L;
    }
    return ((long double)nanoseconds * (long double)frequency_khz) /
           ((long double)bytes * 1000000.0L);
}
