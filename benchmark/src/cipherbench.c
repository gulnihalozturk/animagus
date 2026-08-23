/*
 * Animagus cycles-per-byte benchmark.
 *
 * Portions of the benchmark structure and reporting format are adapted from
 * Google's cipherbench, Copyright 2018 Google LLC, under the MIT License.
 * https://opensource.org/licenses/MIT
 */
#include "cipherbench.h"

#include "bench_time.h"
#include "cipher_benchmark_template.h"

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    OPT_BUFSIZE = 1,
    OPT_NTRIES,
    OPT_TOTAL_BYTES,
    OPT_KEY_SIZE,
    OPT_BACKEND,
    OPT_HELP,
};

static const struct option long_options[] = {
    {"bufsize", required_argument, NULL, OPT_BUFSIZE},
    {"ntries", required_argument, NULL, OPT_NTRIES},
    {"total-bytes", required_argument, NULL, OPT_TOTAL_BYTES},
    {"key-size", required_argument, NULL, OPT_KEY_SIZE},
    {"backend", required_argument, NULL, OPT_BACKEND},
    {"help", no_argument, NULL, OPT_HELP},
    {NULL, 0, NULL, 0},
};

static int fail_message(const char *message)
{
    fprintf(stderr, "animagus-cipherbench: %s\n", message);
    return 1;
}

static int fail_errno(const char *operation)
{
    fprintf(stderr, "animagus-cipherbench: %s: %s\n", operation,
            strerror(errno));
    return 1;
}

static void usage(FILE *stream)
{
    fputs("Usage: animagus-cipherbench [OPTION...]\n"
          "  --bufsize=BYTES       message size (at least 32; default 4096)\n"
          "  --ntries=COUNT        timing trials (at least 1; default 5)\n"
          "  --total-bytes=BYTES   bytes per trial before rounding up\n"
          "                         (at least bufsize; default 1048576)\n"
          "  --key-size=BITS       AES key size: 128, 192, or 256 (default 256)\n"
          "  --backend=NAME        auto, portable, or hardware (default auto)\n"
          "  --help                display this help\n",
          stream);
}

static int parse_size(const char *text, size_t *value)
{
    char *end;
    unsigned long long parsed;

    const unsigned char *character = (const unsigned char *)text;

    if (*character == '\0') {
        return -1;
    }
    while (*character != '\0') {
        if (isdigit(*character) == 0) {
            return -1;
        }
        ++character;
    }
    errno = 0;
    parsed = strtoull(text, &end, 10);
    if (errno == ERANGE || end == text || *end != '\0' ||
        parsed > (unsigned long long)SIZE_MAX) {
        return -1;
    }
    *value = (size_t)parsed;
    return 0;
}

static int parse_backend(const char *text, enum animagus_backend *backend)
{
    if (strcmp(text, "auto") == 0) {
        *backend = ANIMAGUS_BACKEND_AUTO;
    } else if (strcmp(text, "portable") == 0) {
        *backend = ANIMAGUS_BACKEND_PORTABLE;
    } else if (strcmp(text, "hardware") == 0) {
        *backend = ANIMAGUS_BACKEND_HARDWARE;
    } else {
        return -1;
    }
    return 0;
}

static bool is_exact_long_option(const char *name, size_t length)
{
    size_t index;

    for (index = 0U; long_options[index].name != NULL; ++index) {
        if (strlen(long_options[index].name) == length &&
            strncmp(long_options[index].name, name, length) == 0) {
            return true;
        }
    }
    return false;
}

static int reject_abbreviated_long_options(int argc, char *const argv[])
{
    int index;

    for (index = 1; index < argc; ++index) {
        const char *argument = argv[index];
        const char *name;
        const char *equals;
        size_t length;

        if (strcmp(argument, "--") == 0) {
            break;
        }
        if (strncmp(argument, "--", 2U) != 0 || argument[2] == '\0') {
            continue;
        }
        name = argument + 2;
        equals = strchr(name, '=');
        length = equals == NULL ? strlen(name) : (size_t)(equals - name);
        if (!is_exact_long_option(name, length)) {
            return fail_message("long option names must be exact");
        }
    }
    return 0;
}

static int parse_options(int argc, char **argv,
                         struct cipherbench_params *params)
{
    int option;

    if (reject_abbreviated_long_options(argc, argv) != 0) {
        return 1;
    }
    *params = (struct cipherbench_params){
        .bufsize = 4096U,
        .ntries = 5U,
        .total_bytes = 1048576U,
        .key_size_bits = 256U,
        .backend = ANIMAGUS_BACKEND_AUTO,
    };
    opterr = 0;
    while ((option = getopt_long(argc, argv, "", long_options, NULL)) != -1) {
        switch (option) {
        case OPT_BUFSIZE:
            if (parse_size(optarg, &params->bufsize) != 0) {
                return fail_message("--bufsize must be a non-negative integer");
            }
            break;
        case OPT_NTRIES:
            if (parse_size(optarg, &params->ntries) != 0) {
                return fail_message("--ntries must be a non-negative integer");
            }
            break;
        case OPT_TOTAL_BYTES:
            if (parse_size(optarg, &params->total_bytes) != 0) {
                return fail_message("--total-bytes must be a non-negative integer");
            }
            break;
        case OPT_KEY_SIZE:
            if (parse_size(optarg, &params->key_size_bits) != 0) {
                return fail_message("--key-size must be an integer");
            }
            break;
        case OPT_BACKEND:
            if (parse_backend(optarg, &params->backend) != 0) {
                return fail_message("--backend must be auto, portable, or hardware");
            }
            break;
        case OPT_HELP:
            usage(stdout);
            return 2;
        default:
            usage(stderr);
            return 1;
        }
    }
    if (optind != argc) {
        return fail_message("positional arguments are not supported");
    }
    if (params->bufsize < ANIMAGUS_MIN_MESSAGE_SIZE) {
        return fail_message("--bufsize must be at least 32");
    }
    if (params->ntries == 0U) {
        return fail_message("--ntries must be at least 1");
    }
    if (params->total_bytes < params->bufsize) {
        return fail_message("--total-bytes must be at least --bufsize");
    }
    if (params->key_size_bits != 128U && params->key_size_bits != 192U &&
        params->key_size_bits != 256U) {
        return fail_message("--key-size must be 128, 192, or 256");
    }
    return 0;
}

static uint64_t xorshift64(uint64_t *state)
{
    uint64_t value = *state;

    value ^= value << 13U;
    value ^= value >> 7U;
    value ^= value << 17U;
    *state = value;
    return value;
}

static void fill_deterministic(uint8_t *bytes, size_t length, uint64_t *state)
{
    size_t index;

    for (index = 0U; index < length; ++index) {
        bytes[index] = (uint8_t)xorshift64(state);
    }
}

static int round_total_bytes(size_t total_bytes, size_t bufsize,
                             size_t *rounded_bytes, size_t *messages)
{
    size_t remainder = total_bytes % bufsize;
    size_t add = remainder == 0U ? 0U : bufsize - remainder;

    if (total_bytes > SIZE_MAX - add) {
        return fail_message("rounded --total-bytes exceeds supported range");
    }
    *rounded_bytes = total_bytes + add;
    *messages = *rounded_bytes / bufsize;
    return 0;
}

static const char *backend_name(enum animagus_backend backend)
{
    switch (backend) {
    case ANIMAGUS_BACKEND_PORTABLE:
        return "portable";
    case ANIMAGUS_BACKEND_HARDWARE:
        return "hardware";
    case ANIMAGUS_BACKEND_AUTO:
    default:
        return "auto";
    }
}

static int init_context(animagus_ctx *ctx, const uint8_t *key, size_t key_len,
                        enum animagus_backend requested,
                        enum animagus_backend *selected)
{
    animagus_ctx hardware_probe;
    int status;

    status = animagus_init_ex(ctx, key, key_len, requested);
    if (status != ANIMAGUS_OK) {
        return fail_message("Animagus context initialization failed");
    }
    if (requested != ANIMAGUS_BACKEND_AUTO) {
        *selected = requested;
        return 0;
    }
    status = animagus_init_ex(&hardware_probe, key, key_len,
                              ANIMAGUS_BACKEND_HARDWARE);
    if (status == ANIMAGUS_OK) {
        animagus_clear(&hardware_probe);
        *selected = ANIMAGUS_BACKEND_HARDWARE;
    } else {
        *selected = ANIMAGUS_BACKEND_PORTABLE;
    }
    return 0;
}

static void show_result(const char *algorithm, const char *operation,
                        const char *backend, size_t bytes, uint64_t elapsed,
                        uint64_t frequency_khz)
{
    char heading[96];
    uint64_t throughput = bench_kb_per_second(bytes, elapsed);

    (void)snprintf(heading, sizeof(heading), "%s %s (%s) ", algorithm,
                   operation, backend);
    if (frequency_khz != 0U && elapsed != 0U) {
        printf("%-45s %6.3Lf cpb (%" PRIu64 " KB/s)\n", heading,
               bench_cycles_per_byte(bytes, elapsed, frequency_khz),
               throughput);
    } else {
        printf("%-45s %" PRIu64 " KB/s\n", heading, throughput);
    }
    printf("RESULT algorithm=%s operation=%s backend=%s bytes=%zu "
           "nanoseconds=%" PRIu64 " kb_per_second=%" PRIu64 "\n",
           algorithm, operation, backend, bytes, elapsed, throughput);
}

int cipherbench_run(const struct cipherbench_params *params)
{
    uint8_t key[32];
    uint8_t tweak[ANIMAGUS_BLOCK_SIZE];
    uint8_t *plaintext = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *recovered = NULL;
    const size_t key_bytes = params->key_size_bits / 8U;
    const char *selected_backend_name;
    char algorithm[32];
    uint64_t random_state = UINT64_C(0x9e3779b97f4a7c15);
    uint64_t encryption_time;
    uint64_t decryption_time;
    uint64_t frequency_khz = 0U;
    size_t rounded_bytes;
    size_t messages;
    enum animagus_backend selected_backend;
    animagus_ctx context;
    bool context_ready = false;
    int result = 1;

    if (round_total_bytes(params->total_bytes, params->bufsize, &rounded_bytes,
                          &messages) != 0) {
        return 1;
    }
    plaintext = malloc(params->bufsize);
    ciphertext = malloc(params->bufsize);
    recovered = malloc(params->bufsize);
    if (plaintext == NULL || ciphertext == NULL || recovered == NULL) {
        result = fail_message("buffer allocation failed");
        goto out;
    }
    fill_deterministic(key, key_bytes, &random_state);
    fill_deterministic(tweak, sizeof(tweak), &random_state);
    fill_deterministic(plaintext, params->bufsize, &random_state);
    if (init_context(&context, key, key_bytes, params->backend,
                     &selected_backend) != 0) {
        goto out;
    }
    context_ready = true;
    if (animagus_encrypt(&context, ciphertext, plaintext, params->bufsize,
                         tweak, sizeof(tweak)) != ANIMAGUS_OK ||
        animagus_decrypt(&context, recovered, ciphertext, params->bufsize,
                         tweak, sizeof(tweak)) != ANIMAGUS_OK ||
        memcmp(recovered, plaintext, params->bufsize) != 0) {
        result = fail_message("untimed encryption/decryption self-test failed");
        goto out;
    }

    CIPHER_BENCHMARK_MEASURE(encryption_time, result, animagus_encrypt,
                             &context, ciphertext, plaintext, params->bufsize,
                             tweak, sizeof(tweak), messages, params->ntries);
    CIPHER_BENCHMARK_MEASURE(decryption_time, result, animagus_decrypt,
                             &context, recovered, ciphertext, params->bufsize,
                             tweak, sizeof(tweak), messages, params->ntries);
    if (memcmp(recovered, plaintext, params->bufsize) != 0) {
        result = fail_message("timed decryption did not recover plaintext");
        goto out;
    }

    (void)bench_read_max_frequency_khz(&frequency_khz);
    (void)snprintf(algorithm, sizeof(algorithm), "AES-%zu-Animagus",
                   params->key_size_bits);
    selected_backend_name = backend_name(selected_backend);
    show_result(algorithm, "encryption", selected_backend_name, rounded_bytes,
                encryption_time, frequency_khz);
    show_result(algorithm, "decryption", selected_backend_name, rounded_bytes,
                decryption_time, frequency_khz);
    result = 0;

out:
    if (context_ready) {
        animagus_clear(&context);
    }
    free(recovered);
    free(ciphertext);
    free(plaintext);
    return result;
}

int main(int argc, char **argv)
{
    struct cipherbench_params params;
    int status;

    status = parse_options(argc, argv, &params);
    if (status == 2) {
        return 0;
    }
    if (status != 0) {
        return status;
    }
    return cipherbench_run(&params);
}
