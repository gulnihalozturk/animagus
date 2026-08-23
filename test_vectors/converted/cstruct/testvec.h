#pragma once

#include <stddef.h>
#include <stdint.h>

struct testvec_buffer {
    size_t len;
    /* data may be NULL exactly when len is zero. */
    const uint8_t *data;
};
