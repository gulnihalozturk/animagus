/*
 * Animagus cipher benchmark interface.
 *
 * Portions of the benchmark structure and reporting format are adapted from
 * Google's cipherbench, Copyright 2018 Google LLC, under the MIT License.
 * https://opensource.org/licenses/MIT
 */
#pragma once

#include <stddef.h>

#include "animagus.h"

struct cipherbench_params {
    size_t bufsize;
    size_t ntries;
    size_t total_bytes;
    size_t key_size_bits;
    enum animagus_backend backend;
};

int cipherbench_run(const struct cipherbench_params *params);
