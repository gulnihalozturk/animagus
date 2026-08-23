# Benchmarking Animagus

The benchmark measures this repository's concrete AES-Animagus implementation.
It reports engineering results for one machine, compiler, and build
configuration, not intrinsic protocol properties.

## Setup and runs

Install Meson and Ninja, then configure an optimized build from the repository
root:

```sh
meson setup build/release --buildtype=release
meson compile -C build/release
./build/release/benchmark/animagus-cipherbench --help
```

Use `meson setup --reconfigure build/release --buildtype=release` when
refreshing a compatible existing directory, or `--wipe` when it cannot be
reused. Always benchmark the release configuration: the
scalar SHA3 code is several times faster at `-O3` than at `-O2`, and a plain
`debug` setup (`-O0`) understates throughput by an order of magnitude.
Record the compiler, flags, and CPU alongside any figures you keep.

A representative pair of runs is:

```sh
./build/release/benchmark/animagus-cipherbench \
  --bufsize=512 --ntries=25 --key-size=256 --backend=auto
./build/release/benchmark/animagus-cipherbench \
  --bufsize=4096 --ntries=25 --key-size=256 --backend=auto
```

Standalone defaults are a 4096-byte message, five trials, at least 1,048,576
bytes processed per trial, a 256-bit key, and the `auto` backend. The total is
rounded up to a whole number of messages. Accepted key sizes are 128, 192, and
256 bits; accepted backends are `auto`, `portable`, and `hardware`.

## What is timed

The benchmark allocates and fills its buffers and initializes the keyed
Animagus context before timing, so allocation and key setup are excluded. It
then performs one untimed encryption/decryption self-test, which also acts as a
warm-up and prevents reporting a backend that fails to round-trip.

Encryption and decryption are timed independently with `CLOCK_MONOTONIC`. Each
trial processes the rounded byte total, and the fastest elapsed time (the
best-of-N selection) is reported for each operation. Results therefore
represent steady-state throughput under favorable observed scheduling rather
than a latency distribution. The `RESULT` field named `bytes` is the rounded
total processed per trial.

Throughput is decimal KB/s:

```text
KB_PER_SECOND = BYTES * 1,000,000 / ELAPSED_NANOSECONDS
```

When the executable can read Linux
`/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq`, it estimates cycles
per byte as:

```text
cycles per byte = ELAPSED_NANOSECONDS * CPU_KHZ
                  / (BYTES * 1,000,000)
```

If that maximum-frequency file is unavailable, the executable reports
throughput without a cycles-per-byte value; it never invents a frequency.

## Interpretation

Frequency-derived cycles per byte are estimates. A configured or advertised
maximum frequency is not necessarily the core frequency during each trial;
turbo behavior, thermal and power limits, VM scheduling, background work, and
frequency reporting can all bias it. Best-of-N selection intentionally favors
the least disturbed trial and does not describe variance. Treat the numbers
as implementation results for this source tree on the recorded machine.

## Cross-algorithm comparison

`compare_cpb.py` produces the paper's AES-256 comparison table — this
repository's Animagus implementation against HCTR2, Adiantum, TET, HEH,
and an AES-256-XTS baseline — with one uniform methodology. It builds
unmodified checkouts of [google/hctr2](https://github.com/google/hctr2),
[google/adiantum](https://github.com/google/adiantum), and the TET/HEH
benchmark repository, expected at `../hctr2`, `../adiantum`, and `../tet`
(override with `--hctr2` / `--adiantum` / `--tet`).

The benchmarks build and run on any x86-64 Linux system with AES-NI, a C
toolchain, Meson, and Ninja. One-time setup on Debian/Ubuntu (including under WSL):

```sh
sudo apt install build-essential meson ninja-build python3-pytest
```

Run from Linux, at the repository root:

```sh
python3 benchmark/compare_cpb.py
```

On Windows, run the same command inside WSL from the repository root:

```sh
wsl python3 benchmark/compare_cpb.py
```

(add `-d <distro>` if the toolchain lives in a distro other than your
default). Nothing depends on WSL or on any particular machine: the
sibling checkouts are located relative to this repository (`../hctr2`,
`../adiantum`, `../tet`) or wherever `--hctr2` / `--adiantum` / `--tet`
point.

`--quick` runs a 3-trial smoke pass. Each run writes
`benchmark/results/comparison-<timestamp>.{json,md,tex}` — the console
table as Markdown, a bare booktabs tabular, and a JSON archive holding
raw benchmark output and full provenance — plus
`comparison-<timestamp>-paper.tex`, a paste-ready `\begin{table}` float
with caption, label, and provenance comments. Unit and temporary-Git
integration tests run on any host with Python, pytest, and Git:
`python3 -m pytest benchmark/test_compare_cpb.py`. The real Meson
reconfiguration test runs when Meson is available and otherwise reports a
skip.

Unless `--no-build` is supplied, the comparison script always configures or
reconfigures every dedicated `build/cpb-compare` tree with
`--buildtype=release` before compilation. It then introspects all four trees
and refuses to benchmark if any effective build type is non-release or
unknown. The same release-only validation applies to `--no-build`, preventing
an old debug binary from producing a paste-ready table.

### Methodology

- Every number is best-of-N trials (default 25) as reported by each
  repository's own benchmark binary. The script recomputes cycles per
  byte itself from a single CPU frequency so that all rows share one
  methodology; the cpb values the sibling binaries print are archived in
  the JSON but never used for the table.
- The frequency defaults to the first `cpu MHz` line of `/proc/cpuinfo`,
  a nominal value: cores may run turbo above it or throttle below it, so
  treat default cpb as approximate. For final published numbers, pass
  `--cpu-mhz` with a pinned or measured core frequency. An explicit value
  must be finite and strictly positive.
- The adiantum benchmark is built with `-Dc_args=-mssse3`: upstream gates
  its x86-64 ChaCha SIMD on compile-time SSSE3, and a default build would
  report no accelerated Adiantum rows at all (its accelerated label shows
  as `SSE2`, upstream's own name for that configuration). hctr2 and
  animagus need no extra flags.
- The AES-256-XTS baseline pairs two sources: upstream hctr2 implements
  only an accelerated (AES-NI) XTS benchmark, so the generic XTS row is
  measured from the adiantum benchmark's portable C implementation, while
  the accelerated XTS row comes from hctr2. Both are recomputed under the
  same single-frequency methodology as every other row.
- The TET and HEH rows come from the TET/HEH benchmark repository, which
  provides both a generic C and an AES-NI (`simd`) implementation for
  each, in the same cipherbench format; no extra build flags are needed.
  Its HEHfp variant is benchmarked and archived in the JSON but not shown
  in the table.
- Record the upstream hctr2, adiantum, and tet commits — captured in the
  JSON provenance and the LaTeX header comments — next to any published
  table.
- Dirty provenance checks tracked worktree changes with CR-at-EOL differences
  ignored, then checks staged and untracked changes separately. This keeps the
  documented Windows/WSL workflow from reporting a clean CRLF checkout as
  modified while still recording substantive, staged, and untracked changes.
- Portable/generic rows identify each repository's C implementation but make
  no blanket constant-time claim. See the root README for Animagus's
  backend-specific side-channel posture.

The pre-existing `build/compare` and `*/benchmark/build/animagus-compare`
directories left by earlier experiments contain stale absolute paths;
`compare_cpb.py` never touches them and they can be deleted.
