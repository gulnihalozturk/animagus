#!/usr/bin/env python3
"""Cross-algorithm cycles-per-byte comparison for the Animagus paper.

Builds this repository's benchmark plus pristine sibling checkouts of
google/hctr2, google/adiantum, and the TET/HEH cipherbench (tet), runs one
uniform AES-256 benchmark matrix, computes cycles per byte from a single
CPU frequency, and renders the comparison table as console/Markdown,
LaTeX, and a JSON archive.

Python >= 3.8, standard library only. Benchmarks run on Linux only; focused
unit and temporary-repository integration tests run on supported host OSes.
"""

import argparse
import json
import math
import platform
import re
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = 1
DEFAULT_NTRIES = 25
QUICK_NTRIES = 3

# Upstream show_result() in both hctr2 and adiantum prints e.g.
#   AES-128-HCTR2 encryption (generic)            62.549 cpb (51031 KB/s)
# An unpatched binary prints "0.000" cpb when it cannot detect a frequency;
# the printed cpb is archived but never used for the table.
SIBLING_RESULT_RE = re.compile(
    r"^(.+?) (encryption|decryption) \((.+?)\)\s+([0-9.]+) cpb"
    r" \((\d+) KB/s\)$")


def parse_sibling_output(text):
    """Parse hctr2/adiantum cipherbench stdout into result-row dicts.

    Non-matching lines (frequency preamble, parameter block, blanks,
    warnings) are skipped.
    """
    rows = []
    for line in text.splitlines():
        match = SIBLING_RESULT_RE.match(line)
        if match is None:
            continue
        rows.append({
            "algorithm": match.group(1),
            "operation": match.group(2),
            "impl": match.group(3),
            "printed_cpb": float(match.group(4)),
            "kb_per_second": int(match.group(5)),
            "bytes": None,
            "nanoseconds": None,
        })
    return rows


# animagus-cipherbench prints one machine-readable line per operation:
#   RESULT algorithm=AES-256-Animagus operation=encryption backend=hardware
#     bytes=1048576 nanoseconds=13641700 kb_per_second=76865
# "bytes" is the rounded total processed per trial, not the bufsize; the
# bufsize is attached from the invocation that produced the line.
ANIMAGUS_RESULT_RE = re.compile(
    r"^RESULT algorithm=(\S+) operation=(\S+) backend=(\S+)"
    r" bytes=(\d+) nanoseconds=(\d+) kb_per_second=(\d+)$")


def parse_animagus_output(text):
    """Parse animagus-cipherbench stdout; only RESULT lines are used."""
    rows = []
    for line in text.splitlines():
        match = ANIMAGUS_RESULT_RE.match(line)
        if match is None:
            continue
        rows.append({
            "algorithm": match.group(1),
            "operation": match.group(2),
            "impl": match.group(3),
            "printed_cpb": None,
            "kb_per_second": int(match.group(6)),
            "bytes": int(match.group(4)),
            "nanoseconds": int(match.group(5)),
        })
    return rows


def cpb_from_exact(nanoseconds, nbytes, cpu_mhz):
    """Cycles per byte from elapsed nanoseconds and bytes processed.

    cycles = nanoseconds * kHz / 1e6, so cpb = ns * (mhz*1000) / (bytes*1e6).
    """
    return (nanoseconds * cpu_mhz * 1000.0) / (nbytes * 1e6)


def cpb_from_kbps(kb_per_second, cpu_mhz):
    """Cycles per byte from decimal-KB/s throughput at cpu_mhz.

    Same formula as cpb_from_exact rearranged through the printed
    throughput; the integer rounding of KB/s contributes < 1e-4 relative
    error, invisible at two decimals.
    """
    if kb_per_second == 0:
        raise FatalError(
            "cannot derive cycles per byte from a 0 KB/s benchmark row")
    return (cpu_mhz * 1000.0) / kb_per_second


def compute_cpb(row, cpu_mhz):
    """Exact-field path for animagus rows, KB/s path for sibling rows."""
    if row["nanoseconds"] is not None and row["bytes"] is not None:
        return cpb_from_exact(row["nanoseconds"], row["bytes"], cpu_mhz)
    return cpb_from_kbps(row["kb_per_second"], cpu_mhz)


CPUINFO_MHZ_RE = re.compile(r"^cpu MHz\s*:\s*([0-9.]+)", re.MULTILINE)
CPUINFO_MODEL_RE = re.compile(r"^model name\s*:\s*(.+)$", re.MULTILINE)


def parse_cpuinfo_mhz(text):
    """First 'cpu MHz' value of /proc/cpuinfo text, or None."""
    match = CPUINFO_MHZ_RE.search(text)
    return float(match.group(1)) if match else None


def parse_cpuinfo_model(text):
    """First 'model name' value of /proc/cpuinfo text, or None."""
    match = CPUINFO_MODEL_RE.search(text)
    return match.group(1).strip() if match else None


# Sentinel for "the fastest non-generic implementation" in TABLE_SPEC.
ACCELERATED = "accelerated"

# The table rows, in fixed order: (tool, algorithm, impl-or-sentinel).
#
# AES-256-XTS is split across both siblings, because neither alone prints
# a full generic+accelerated pair:
#   - hctr2's benchmark/src/xts.c never defines the non-SIMD ENCRYPT/
#     DECRYPT macros for XTS at any key size (only ENCRYPT_SIMD/
#     DECRYPT_SIMD, SIMD_IMPL_NAME "simd"), so cipher_benchmark_template.h's
#     "#ifdef ENCRYPT" generic show_result() call is unreachable for XTS --
#     hctr2 supplies the accelerated ("simd") row.
#   - adiantum's benchmark/src/aes.c runs xts_benchmark_template.h from
#     test_aes() (invoked with the "AES" argument); its generic
#     show_result() call is unconditional, but XTS_ENCRYPT_SIMD/
#     XTS_DECRYPT_SIMD are only defined "#ifdef __arm__" -- on x86-64
#     adiantum supplies the generic row and no accelerated XTS row at all.
# Both are structural properties of the pristine upstream sources, not a
# build quirk, verified by reading xts.c/cipher_benchmark_template.h
# (hctr2) and aes.c/xts_benchmark_template.h (adiantum) and by running
# both binaries directly.
TABLE_SPEC = [
    ("animagus", "AES-256-Animagus", "portable"),
    ("animagus", "AES-256-Animagus", "hardware"),
    ("hctr2", "AES-256-HCTR2", "generic"),
    ("hctr2", "AES-256-HCTR2", ACCELERATED),
    ("adiantum", "Adiantum-XChaCha12-AES", "generic"),
    ("adiantum", "Adiantum-XChaCha12-AES", ACCELERATED),
    ("tet", "AES-256-TET", "generic"),
    ("tet", "AES-256-TET", ACCELERATED),
    ("tet", "AES-256-HEH", "generic"),
    ("tet", "AES-256-HEH", ACCELERATED),
    ("adiantum", "AES-256-XTS", "generic"),
    ("hctr2", "AES-256-XTS", ACCELERATED),
]


class MissingRowsError(ValueError):
    """The archive cannot supply every table row; never render
    a partial table."""

    def __init__(self, missing):
        self.missing = list(missing)
        super().__init__(
            "cannot assemble the comparison table; missing rows:\n  " +
            "\n  ".join(self.missing))


def pick_accelerated_impl(rows, tool, algorithm, bufsize):
    """Label of the non-generic impl with the highest encryption KB/s at
    the given bufsize, or None when only generic rows exist."""
    candidates = [
        row for row in rows
        if row["tool"] == tool and row["algorithm"] == algorithm and
        row["impl"] != "generic" and row["operation"] == "encryption" and
        row["bufsize"] == bufsize
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda row: row["kb_per_second"])["impl"]


def select_table_rows(rows, bufsizes):
    """Pick the fixed table rows from the archive.

    Returns a list of {"algorithm", "impl", "cells"} dicts in TABLE_SPEC
    order, where cells maps (bufsize, operation) to the archive row.
    Raises MissingRowsError listing every absent cell.
    """
    largest = max(bufsizes)
    table = []
    missing = []
    for tool, algorithm, impl_spec in TABLE_SPEC:
        if impl_spec == ACCELERATED:
            impl = pick_accelerated_impl(rows, tool, algorithm, largest)
            if impl is None:
                missing.append(
                    "%s accelerated (no non-generic rows)" % algorithm)
                continue
        else:
            impl = impl_spec
        cells = {}
        for bufsize in bufsizes:
            for operation in ("encryption", "decryption"):
                found = [
                    row for row in rows
                    if row["tool"] == tool and
                    row["algorithm"] == algorithm and
                    row["impl"] == impl and
                    row["bufsize"] == bufsize and
                    row["operation"] == operation
                ]
                if found:
                    cells[(bufsize, operation)] = found[0]
                else:
                    missing.append("%s (%s) %s at %d B" %
                                   (algorithm, impl, operation, bufsize))
        table.append({"algorithm": algorithm, "impl": impl, "cells": cells})
    if missing:
        raise MissingRowsError(missing)
    return table


def format_cell(row, unit):
    """One table value: cpb to two decimals, or the integer KB/s."""
    if unit == "cpb":
        return "%.2f" % row["cpb"]
    return str(row["kb_per_second"])


def unit_description(unit, meta):
    if unit == "cpb":
        return ("cycles per byte at %g MHz (%s), best of %d trials, "
                "lower is better" %
                (meta["cpu_mhz"], meta["cpu_mhz_source"], meta["ntries"]))
    return ("KB/s, best of %d trials, higher is better "
            "(CPU frequency unavailable)" % meta["ntries"])


def render_markdown(table, bufsizes, unit, meta):
    """The Markdown table; the console output prints this same string."""
    lines = ["AES-256, %s." % unit_description(unit, meta), ""]
    header = ["Algorithm", "Impl"]
    header += ["%d B enc/dec" % bufsize for bufsize in bufsizes]
    lines.append("| " + " | ".join(header) + " |")
    lines.append("|" + "|".join("---" for _ in header) + "|")
    for entry in table:
        cells = [entry["algorithm"], entry["impl"]]
        for bufsize in bufsizes:
            enc = format_cell(entry["cells"][(bufsize, "encryption")], unit)
            dec = format_cell(entry["cells"][(bufsize, "decryption")], unit)
            cells.append("%s / %s" % (enc, dec))
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def render_latex(table, bufsizes, unit, meta):
    """A booktabs tabular intended for \\input into the paper."""

    def describe_repo(name):
        info = meta["repos"][name]
        commit = (info["commit"] or "unknown")[:12]
        dirty = " dirty" if info["dirty"] else ""
        return "%s %s%s" % (name, commit, dirty)

    lines = [
        "%% Generated by benchmark/compare_cpb.py on %s" %
        meta["generated_utc"],
        "% " + ", ".join(describe_repo(name) for name in meta["repos"]),
        "%% CPU %s, %s" % (meta["cpu_model"] or "unknown",
                           unit_description(unit, meta)),
        r"\begin{tabular}{ll%s}" % ("rr" * len(bufsizes)),
        r"\toprule",
        " & & " + " & ".join(r"\multicolumn{2}{c}{%d B}" % bufsize
                             for bufsize in bufsizes) + r" \\",
        " ".join(r"\cmidrule(lr){%d-%d}" % (3 + 2 * index, 4 + 2 * index)
                 for index in range(len(bufsizes))),
        "Algorithm & Impl. & " +
        " & ".join("Enc. & Dec." for _ in bufsizes) + r" \\",
        r"\midrule",
    ]
    for entry in table:
        cells = [entry["algorithm"], entry["impl"]]
        for bufsize in bufsizes:
            cells.append(
                format_cell(entry["cells"][(bufsize, "encryption")], unit))
            cells.append(
                format_cell(entry["cells"][(bufsize, "decryption")], unit))
        lines.append(" & ".join(cells) + r" \\")
    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    return "\n".join(lines) + "\n"


def render_paper_latex(table, bufsizes, unit, meta):
    """A complete, paste-ready table float wrapping the booktabs tabular.

    The comment block repeats the provenance the JSON archive records so
    the .tex file stands alone; extra human-written caveats can be passed
    as meta["notes"], a list of comment lines.
    """

    def describe_repo(name):
        info = meta["repos"][name]
        commit = (info["commit"] or "unknown")[:12]
        dirty = " dirty" if info["dirty"] else ""
        return "%s %s%s" % (name, commit, dirty)

    toolchain = meta.get("toolchain") or {}
    comments = [
        "%% Generated by benchmark/compare_cpb.py on %s" %
        meta["generated_utc"],
        "% " + ", ".join(describe_repo(name) for name in meta["repos"]),
        "%% cc: %s; buildtype: %s" %
        (toolchain.get("cc") or "unknown",
         toolchain.get("buildtype") or "unknown"),
    ]
    if meta["cpu_mhz_source"] == "cpuinfo":
        comments.append(
            "% The frequency is the nominal /proc/cpuinfo value; cores"
            " running turbo above it make true cycle counts higher than"
            " shown. Pass --cpu-mhz with a pinned frequency for final"
            " numbers.")
    for note in meta.get("notes") or []:
        comments.append("%% %s" % note)
    if unit == "cpb":
        values = ("Cycles per byte on %s, best of %d trials, lower is"
                  " better." %
                  (meta["cpu_model"] or "the benchmark machine",
                   meta["ntries"]))
    else:
        values = ("Throughput in decimal KB/s on %s, best of %d trials,"
                  " higher is better (CPU frequency unavailable)." %
                  (meta["cpu_model"] or "the benchmark machine",
                   meta["ntries"]))
    caption = (
        values + " The portable/generic C rows use each repository's"
        " scalar implementation; accelerated rows use its vectorized or AES-NI"
        " implementation, shown under its own label. Animagus hardware"
        " accelerates only the AES component; its SHA-3 remains scalar C."
        " The AES-256-XTS baseline pairs the Adiantum benchmark's C"
        " implementation (generic) with the HCTR2 benchmark's AES-NI"
        " implementation (accelerated). All values are derived by one"
        " harness under the same methodology.")
    tabular = ["  " + line for line in
               render_latex(table, bufsizes, unit, meta).splitlines()
               if not line.startswith("%")]
    lines = comments + [
        r"\begin{table}[t]",
        r"  \centering",
        "  \\caption{%s}" % caption,
        r"  \label{tab:cpb-comparison}",
    ] + tabular + [r"\end{table}"]
    return "\n".join(lines) + "\n"


class FatalError(Exception):
    """Aborts the run; main() prints the message to stderr and exits 1."""


class CommandError(FatalError):
    """A subprocess exited non-zero; carries the command and output tail."""

    def __init__(self, argv, cwd, proc):
        tail = (proc.stdout + "\n" + proc.stderr).splitlines()[-30:]
        super().__init__(
            "command failed with exit status %d: %s (cwd %s)\n%s" %
            (proc.returncode, " ".join(str(a) for a in argv), cwd,
             "\n".join(tail)))
        self.returncode = proc.returncode


def run_command(argv, cwd):
    """Run a subprocess, capturing output; raise CommandError on failure.

    stderr noise from the sibling binaries (cpufreq governor warnings) is
    not an error; only a non-zero exit status is.
    """
    proc = subprocess.run([str(a) for a in argv], cwd=str(cwd),
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True)
    if proc.returncode != 0:
        raise CommandError(argv, cwd, proc)
    return proc


def animagus_root():
    """The repository root, resolved from this file, never the CWD."""
    return Path(__file__).resolve().parent.parent


def parse_args(argv=None):
    root = animagus_root()
    parser = argparse.ArgumentParser(
        prog="compare_cpb.py",
        description="Cross-algorithm cycles-per-byte comparison: "
                    "AES-256 Animagus vs HCTR2, Adiantum, TET, HEH, "
                    "and XTS.")
    parser.add_argument("--hctr2", type=Path,
                        default=root.parent / "hctr2",
                        help="hctr2 repo root (default: %(default)s)")
    parser.add_argument("--adiantum", type=Path,
                        default=root.parent / "adiantum",
                        help="adiantum repo root (default: %(default)s)")
    parser.add_argument("--tet", type=Path,
                        default=root.parent / "tet",
                        help="TET/HEH benchmark repo root "
                             "(default: %(default)s)")
    parser.add_argument("--bufsizes", default="512,4096",
                        help="comma-separated message sizes in bytes "
                             "(default: %(default)s)")
    parser.add_argument("--ntries", type=int, default=None,
                        help="timing trials per operation (default: 25)")
    parser.add_argument("--cpu-mhz", type=float, default=None,
                        help="CPU frequency used for cycles per byte "
                             "(default: first 'cpu MHz' of /proc/cpuinfo)")
    parser.add_argument("--no-build", action="store_true",
                        help="skip building; use existing cpb-compare "
                             "binaries")
    parser.add_argument("--outdir", type=Path,
                        default=root / "benchmark" / "results",
                        help="output directory (default: %(default)s)")
    parser.add_argument("--quick", action="store_true",
                        help="smoke mode: ntries=3 (an explicit --ntries "
                             "wins)")
    args = parser.parse_args(argv)
    try:
        args.bufsizes = [int(part) for part in args.bufsizes.split(",")
                         if part.strip()]
    except ValueError:
        parser.error("--bufsizes must be comma-separated integers")
    if not args.bufsizes or any(size <= 0 for size in args.bufsizes):
        parser.error("--bufsizes must be positive integers")
    if args.ntries is None:
        args.ntries = QUICK_NTRIES if args.quick else DEFAULT_NTRIES
    if args.ntries <= 0:
        parser.error("--ntries must be at least 1")
    # build_repo()/effective_buildtype() join these with a relative
    # build_rel and pass the result as a subprocess argv element (e.g.
    # `meson compile -C <build_dir>`) while also using a *different*
    # relative directory as that subprocess's cwd. A relative --hctr2/
    # --adiantum would then be re-relativized against the child's cwd
    # instead of this process's cwd, landing on the wrong directory.
    # Resolving once here, while the process cwd is still the invocation
    # directory, keeps every downstream path unambiguous.
    args.hctr2 = args.hctr2.resolve()
    args.adiantum = args.adiantum.resolve()
    args.tet = args.tet.resolve()
    return args


def preflight(args):
    if sys.platform != "linux":
        raise FatalError(
            "benchmarks build and run on Linux only; on Windows run the\n"
            "script inside WSL from the repository root, e.g.\n"
            "  wsl python3 benchmark/compare_cpb.py")
    if not args.no_build:
        for tool in ("cc", "meson", "ninja"):
            if shutil.which(tool) is None:
                raise FatalError(
                    "required tool '%s' not found on PATH (install with: "
                    "sudo apt install build-essential meson ninja-build)"
                    % tool)
    for name, repo in (("hctr2", args.hctr2), ("adiantum", args.adiantum),
                       ("tet", args.tet)):
        if not (repo / "benchmark" / "meson.build").is_file():
            raise FatalError(
                "%s checkout at %s has no benchmark/meson.build" %
                (name, repo))


def git_provenance(repo):
    """Record commit and dirty flag; failures are warnings, never errors."""
    info = {"path": str(repo), "commit": None, "dirty": None}
    try:
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(repo),
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True)
        worktree = subprocess.run(
            ["git", "diff", "--quiet", "--ignore-cr-at-eol", "--"],
            cwd=str(repo), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True)
        staged = subprocess.run(
            ["git", "diff", "--cached", "--quiet", "--"],
            cwd=str(repo), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True)
        untracked = subprocess.run(
            ["git", "ls-files", "--others", "--exclude-standard"],
            cwd=str(repo), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True)
    except OSError as error:
        print("warning: git provenance for %s unavailable: %s" %
              (repo, error), file=sys.stderr)
        return info
    if head.returncode == 0:
        info["commit"] = head.stdout.strip()
    else:
        print("warning: could not record a commit for %s" % repo,
              file=sys.stderr)
    if (worktree.returncode in (0, 1) and
            staged.returncode in (0, 1) and
            untracked.returncode == 0):
        info["dirty"] = (worktree.returncode == 1 or
                         staged.returncode == 1 or
                         bool(untracked.stdout.strip()))
    else:
        print("warning: could not determine dirty state for %s" % repo,
              file=sys.stderr)
    if info["dirty"]:
        print("warning: %s has uncommitted changes; recorded as dirty" %
              repo, file=sys.stderr)
    return info


# Upstream adiantum gates its x86-64 ChaCha SIMD code on compile-time
# SSSE3 (benchmark/src/chacha.h); a default build reports no accelerated
# Adiantum rows at all, so the approved 8-row table could never be
# produced.  -mssse3 is a build flag, not a source patch, and is safe on
# any machine that can run the table at all (AES-NI implies SSSE3).
ADIANTUM_SETUP_ARGS = ["-Dc_args=-mssse3"]


def meson_setup(source_dir, build_rel, setup_args):
    preexisting = (source_dir / build_rel).exists()
    configured = (source_dir / build_rel / "build.ninja").is_file()
    argv = ["meson", "setup"]
    if configured:
        argv.append("--reconfigure")
    argv += [build_rel, "--buildtype=release"] + setup_args
    try:
        run_command(argv, cwd=source_dir)
    except CommandError:
        if not preexisting:
            raise
        run_command(["meson", "setup", "--wipe", build_rel,
                     "--buildtype=release"] + setup_args, cwd=source_dir)


def build_repo(source_dir, build_rel, setup_args, targets=None):
    """Configure as release and compile one repo's cpb-compare dir."""
    build_dir = source_dir / build_rel
    meson_setup(source_dir, build_rel, setup_args)
    if targets:
        try:
            run_command(["meson", "compile", "-C", build_dir] + targets,
                        cwd=source_dir)
            return
        except CommandError:
            print("warning: target-scoped compile failed; running a full "
                  "compile", file=sys.stderr)
    run_command(["meson", "compile", "-C", build_dir], cwd=source_dir)


def build_all(root, args):
    build_repo(root, "build/cpb-compare", [],
               targets=["benchmark/animagus-cipherbench"])
    build_repo(args.hctr2 / "benchmark", "build/cpb-compare", [])
    build_repo(args.adiantum / "benchmark", "build/cpb-compare",
               ADIANTUM_SETUP_ARGS)
    build_repo(args.tet / "benchmark", "build/cpb-compare", [])


def binary_paths(root, args):
    return {
        "animagus":
            root / "build/cpb-compare/benchmark/animagus-cipherbench",
        "hctr2": args.hctr2 / "benchmark/build/cpb-compare/cipherbench",
        "adiantum":
            args.adiantum / "benchmark/build/cpb-compare/cipherbench",
        "tet": args.tet / "benchmark/build/cpb-compare/cipherbench",
    }


def effective_buildtype(build_dir):
    """The buildtype meson actually configured, from introspection.

    The sibling projects declare their own default_options; the spec
    requires recording what --buildtype=release composed to.
    """
    try:
        proc = run_command(
            ["meson", "introspect", "--buildoptions", build_dir],
            cwd=build_dir)
        for option in json.loads(proc.stdout):
            if option.get("name") == "buildtype":
                return option.get("value")
    except (FatalError, OSError, ValueError):
        pass
    return None


def validate_release_buildtypes(repos):
    invalid = [
        "%s=%s" % (name, info.get("effective_buildtype") or "unknown")
        for name, info in repos.items()
        if info.get("effective_buildtype") != "release"
    ]
    if invalid:
        raise FatalError(
            "publication benchmarks require Meson buildtype=release; "
            "invalid build trees: %s" % ", ".join(invalid))


def read_cpu_mhz(flag_value):
    """One frequency for the whole run: flag, else cpuinfo, else None."""
    if flag_value is not None:
        if not math.isfinite(flag_value) or flag_value <= 0.0:
            raise FatalError("--cpu-mhz must be a finite positive number")
        return flag_value, "flag"
    try:
        text = Path("/proc/cpuinfo").read_text()
    except OSError:
        text = ""
    mhz = parse_cpuinfo_mhz(text)
    if mhz is not None:
        return mhz, "cpuinfo"
    return None, "unavailable"


def first_line(text):
    return text.strip().splitlines()[0] if text.strip() else None


def tool_version(argv):
    try:
        proc = subprocess.run(argv, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True)
    except OSError:
        return None
    if proc.returncode != 0:
        return None
    return first_line(proc.stdout)


def collect_host(cpu_mhz, cpu_mhz_source):
    try:
        cpuinfo = Path("/proc/cpuinfo").read_text()
    except OSError:
        cpuinfo = ""
    return {
        "hostname": socket.gethostname(),
        "kernel": platform.release(),
        "cpu_model": parse_cpuinfo_model(cpuinfo),
        "cpu_mhz": cpu_mhz,
        "cpu_mhz_source": cpu_mhz_source,
    }


def collect_toolchain(buildtype):
    return {
        "cc": tool_version(["cc", "--version"]),
        "meson": tool_version(["meson", "--version"]),
        "ninja": tool_version(["ninja", "--version"]),
        "buildtype": buildtype,
    }


def invocation_plan(binaries, bufsize, ntries):
    """The five invocations for one bufsize, in fixed order."""
    return [
        ("animagus", [binaries["animagus"], "--bufsize=%d" % bufsize,
                      "--ntries=%d" % ntries, "--key-size=256",
                      "--backend=portable"]),
        ("animagus", [binaries["animagus"], "--bufsize=%d" % bufsize,
                      "--ntries=%d" % ntries, "--key-size=256",
                      "--backend=hardware"]),
        ("hctr2", [binaries["hctr2"], "--bufsize=%d" % bufsize,
                   "--ntries=%d" % ntries, "HCTR2", "XTS"]),
        ("adiantum", [binaries["adiantum"], "--bufsize=%d" % bufsize,
                      "--ntries=%d" % ntries, "Adiantum", "AES"]),
        ("tet", [binaries["tet"], "--bufsize=%d" % bufsize,
                 "--ntries=%d" % ntries, "TET", "HEH", "HEHfp"]),
    ]


def run_matrix(binaries, bufsizes, ntries, root):
    """Run every invocation; archive raw output; parse rows.

    Any non-zero exit is a hard error, including --backend=hardware on a
    machine without AES-NI: the approved table cannot be produced without
    that row.
    """
    invocations = []
    rows = []
    for bufsize in bufsizes:
        for tool, argv in invocation_plan(binaries, bufsize, ntries):
            print("running: %s" % " ".join(str(a) for a in argv),
                  file=sys.stderr)
            proc = run_command(argv, cwd=root)
            invocations.append({
                "tool": tool,
                "bufsize": bufsize,
                "argv": [str(a) for a in argv],
                "raw_stdout": proc.stdout,
                "raw_stderr": proc.stderr,
            })
            if tool == "animagus":
                parsed = parse_animagus_output(proc.stdout)
            else:
                parsed = parse_sibling_output(proc.stdout)
            for row in parsed:
                row["tool"] = tool
                row["bufsize"] = bufsize
                rows.append(row)
    return invocations, rows


def main(argv=None):
    args = parse_args(argv)
    root = animagus_root()
    try:
        preflight(args)
        repos = {
            "animagus": git_provenance(root),
            "hctr2": git_provenance(args.hctr2),
            "adiantum": git_provenance(args.adiantum),
            "tet": git_provenance(args.tet),
        }
        binaries = binary_paths(root, args)
        if args.no_build:
            for tool, binary in binaries.items():
                if not binary.is_file():
                    raise FatalError(
                        "--no-build was given but the %s benchmark binary "
                        "is missing: %s" % (tool, binary))
        else:
            build_all(root, args)
            for tool, binary in binaries.items():
                if not binary.is_file():
                    raise FatalError(
                        "build finished but the %s benchmark binary is "
                        "missing: %s" % (tool, binary))
        repos["animagus"]["setup_args"] = []
        repos["hctr2"]["setup_args"] = []
        repos["adiantum"]["setup_args"] = list(ADIANTUM_SETUP_ARGS)
        repos["tet"]["setup_args"] = []
        repos["animagus"]["effective_buildtype"] = effective_buildtype(
            root / "build/cpb-compare")
        repos["hctr2"]["effective_buildtype"] = effective_buildtype(
            args.hctr2 / "benchmark/build/cpb-compare")
        repos["adiantum"]["effective_buildtype"] = effective_buildtype(
            args.adiantum / "benchmark/build/cpb-compare")
        repos["tet"]["effective_buildtype"] = effective_buildtype(
            args.tet / "benchmark/build/cpb-compare")
        validate_release_buildtypes(repos)
        cpu_mhz, cpu_mhz_source = read_cpu_mhz(args.cpu_mhz)
        unit = "cpb" if cpu_mhz is not None else "kbps"
        if unit == "kbps":
            print("warning: CPU frequency unavailable; reporting KB/s "
                  "instead of cycles per byte (pass --cpu-mhz to fix)",
                  file=sys.stderr)
        invocations, rows = run_matrix(binaries, args.bufsizes,
                                       args.ntries, root)
        for row in rows:
            row["cpb"] = (compute_cpb(row, cpu_mhz)
                          if cpu_mhz is not None else None)
        try:
            table = select_table_rows(rows, args.bufsizes)
        except MissingRowsError as error:
            raise FatalError(str(error))
        generated = datetime.now(timezone.utc)
        generated_utc = generated.strftime("%Y-%m-%dT%H:%M:%SZ")
        host = collect_host(cpu_mhz, cpu_mhz_source)
        toolchain = collect_toolchain(
            repos["animagus"]["effective_buildtype"] or "release")
        meta = {
            "generated_utc": generated_utc,
            "repos": repos,
            "cpu_model": host["cpu_model"],
            "cpu_mhz": cpu_mhz,
            "cpu_mhz_source": cpu_mhz_source,
            "ntries": args.ntries,
            "toolchain": toolchain,
        }
        markdown = render_markdown(table, args.bufsizes, unit, meta)
        latex = render_latex(table, args.bufsizes, unit, meta)
        paper = render_paper_latex(table, args.bufsizes, unit, meta)
        document = {
            "schema": SCHEMA_VERSION,
            "generated_utc": generated_utc,
            "host": host,
            "toolchain": toolchain,
            "repos": repos,
            "params": {
                "bufsizes": args.bufsizes,
                "ntries": args.ntries,
                "argv": sys.argv,
            },
            "invocations": invocations,
            "rows": rows,
        }
        args.outdir.mkdir(parents=True, exist_ok=True)
        stamp = generated.strftime("%Y%m%d-%H%M%S")
        base = args.outdir / ("comparison-%s" % stamp)
        json_path = base.with_suffix(".json")
        md_path = base.with_suffix(".md")
        tex_path = base.with_suffix(".tex")
        paper_path = args.outdir / ("comparison-%s-paper.tex" % stamp)
        json_path.write_text(json.dumps(document, indent=2) + "\n")
        md_path.write_text(markdown)
        tex_path.write_text(latex)
        paper_path.write_text(paper)
        print()
        print(markdown)
        for path in (json_path, md_path, tex_path, paper_path):
            print("wrote %s" % path)
        return 0
    except FatalError as error:
        print("compare_cpb: error: %s" % error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
