#pragma once

#include "aes.h"

#include <stddef.h>
#include <stdint.h>

void animagus_ctr_counter(uint8_t out[16], const uint8_t seed[16],
                          uint64_t index);
void animagus_ctr_crypt(const struct animagus_aes_ctx *ctx, uint8_t *out,
                        const uint8_t *in, size_t length,
                        const uint8_t seed[16]);
