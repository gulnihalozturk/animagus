"""Unit and focused integration tests for benchmark/compare_cpb.py."""

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import compare_cpb


HCTR2_OUTPUT = """\
Detected max CPU frequency: 3192.000 MHz
Benchmark parameters:
\tbufsize\t\t512
\tntries\t\t25

AES-128-HCTR2 encryption (generic)            62.549 cpb (51031 KB/s)
AES-128-HCTR2 decryption (generic)            63.062 cpb (50616 KB/s)
AES-128-HCTR2 encryption (simd)                2.573 cpb (1240544 KB/s)
AES-128-HCTR2 decryption (simd)                2.582 cpb (1236217 KB/s)
AES-256-HCTR2 encryption (generic)            77.859 cpb (40996 KB/s)
AES-256-HCTR2 decryption (generic)            78.056 cpb (40893 KB/s)
AES-256-HCTR2 encryption (simd)                3.283 cpb (972282 KB/s)
AES-256-HCTR2 decryption (simd)                3.294 cpb (969034 KB/s)
AES-256-XTS encryption (generic)              33.077 cpb (96501 KB/s)
AES-256-XTS decryption (generic)              33.214 cpb (96103 KB/s)
AES-256-XTS encryption (simd)                  0.599 cpb (5329215 KB/s)
AES-256-XTS decryption (simd)                  0.611 cpb (5224536 KB/s)
"""

UNPATCHED_OUTPUT = """\
Unable to query CPU frequency: No such file or directory
Benchmark parameters:
\tbufsize\t\t4096
\tntries\t\t3

Adiantum-XChaCha20-AES encryption (generic)    0.000 cpb (66225 KB/s)
Adiantum-XChaCha20-AES decryption (generic)    0.000 cpb (66123 KB/s)
Adiantum-XChaCha12-AES encryption (SSE2)       0.000 cpb (183486 KB/s)
"""


def test_sibling_parser_extracts_result_lines():
    rows = compare_cpb.parse_sibling_output(HCTR2_OUTPUT)
    assert len(rows) == 12
    first = rows[0]
    assert first["algorithm"] == "AES-128-HCTR2"
    assert first["operation"] == "encryption"
    assert first["impl"] == "generic"
    assert first["printed_cpb"] == pytest.approx(62.549)
    assert first["kb_per_second"] == 51031
    assert first["bytes"] is None
    assert first["nanoseconds"] is None
    huge = [row for row in rows if row["kb_per_second"] == 5329215]
    assert len(huge) == 1
    assert huge[0]["algorithm"] == "AES-256-XTS"


def test_sibling_parser_skips_noise_and_accepts_zero_cpb():
    rows = compare_cpb.parse_sibling_output(UNPATCHED_OUTPUT)
    assert [row["algorithm"] for row in rows] == [
        "Adiantum-XChaCha20-AES", "Adiantum-XChaCha20-AES",
        "Adiantum-XChaCha12-AES"]
    assert rows[0]["printed_cpb"] == 0.0
    assert rows[2]["impl"] == "SSE2"
    assert rows[2]["kb_per_second"] == 183486


ANIMAGUS_OUTPUT = """\
AES-256-Animagus encryption (hardware)         41.527 cpb (76865 KB/s)
AES-256-Animagus decryption (hardware)        77191 KB/s
RESULT algorithm=AES-256-Animagus operation=encryption backend=hardware bytes=1048576 nanoseconds=13641700 kb_per_second=76865
RESULT algorithm=AES-256-Animagus operation=decryption backend=hardware bytes=1048576 nanoseconds=13584100 kb_per_second=77191
"""


def test_animagus_parser_reads_only_result_lines():
    rows = compare_cpb.parse_animagus_output(ANIMAGUS_OUTPUT)
    assert len(rows) == 2
    assert rows[0] == {
        "algorithm": "AES-256-Animagus",
        "operation": "encryption",
        "impl": "hardware",
        "printed_cpb": None,
        "kb_per_second": 76865,
        "bytes": 1048576,
        "nanoseconds": 13641700,
    }
    assert rows[1]["operation"] == "decryption"
    assert rows[1]["nanoseconds"] == 13584100


def test_sibling_repo_paths_resolve_to_absolute():
    # build_repo()/effective_buildtype() join --hctr2/--adiantum with a
    # relative build_rel and pass the result as a subprocess argv element
    # (e.g. `meson compile -C <build_dir>`) while giving that subprocess a
    # *different* relative cwd; a relative --hctr2/--adiantum would then be
    # re-relativized against the child's cwd instead of this process's,
    # landing on the wrong directory. parse_args must resolve both to
    # absolute paths so downstream joins are unambiguous regardless of
    # which cwd a subprocess call uses.
    args = compare_cpb.parse_args([
        "--hctr2", "../../somewhere/hctr2",
        "--adiantum", "../../somewhere/adiantum",
        "--tet", "../../somewhere/tet",
    ])
    assert args.hctr2.is_absolute()
    assert args.adiantum.is_absolute()
    assert args.tet.is_absolute()
    assert args.hctr2.name == "hctr2"
    assert args.adiantum.name == "adiantum"
    assert args.tet.name == "tet"


CPUINFO_SAMPLE = """\
processor\t: 0
vendor_id\t: GenuineIntel
model name\t: Intel(R) Core(TM) i7-8700 CPU @ 3.20GHz
cpu MHz\t\t: 3192.001
processor\t: 1
model name\t: Intel(R) Core(TM) i7-8700 CPU @ 3.20GHz
cpu MHz\t\t: 3191.998
"""


def test_cpb_from_kbps_matches_hand_computation():
    # 51031 decimal KB/s at 3192 MHz: 3192000 kHz / 51031 = 62.55 cpb.
    assert compare_cpb.cpb_from_kbps(51031, 3192.0) == pytest.approx(
        62.55, abs=0.01)


def test_cpb_from_exact_matches_hand_computation():
    # 1048576 bytes in 13641700 ns at 3192 MHz:
    # 13641700 * 3192000 / (1048576 * 1e6) = 41.53 cpb.
    assert compare_cpb.cpb_from_exact(13641700, 1048576, 3192.0) == \
        pytest.approx(41.53, abs=0.01)


def test_exact_and_kbps_paths_agree():
    row_exact = {"bytes": 1048576, "nanoseconds": 13641700,
                 "kb_per_second": 76865}
    row_kbps = {"bytes": None, "nanoseconds": None, "kb_per_second": 76865}
    exact = compare_cpb.compute_cpb(row_exact, 3192.0)
    approx = compare_cpb.compute_cpb(row_kbps, 3192.0)
    assert approx == pytest.approx(exact, rel=1e-4)


def test_zero_kbps_raises_fatal_error():
    with pytest.raises(compare_cpb.FatalError):
        compare_cpb.cpb_from_kbps(0, 3192.0)


def test_cpuinfo_mhz_takes_first_entry():
    assert compare_cpb.parse_cpuinfo_mhz(CPUINFO_SAMPLE) == pytest.approx(
        3192.001)


def test_cpuinfo_model_extraction():
    assert compare_cpb.parse_cpuinfo_model(CPUINFO_SAMPLE) == (
        "Intel(R) Core(TM) i7-8700 CPU @ 3.20GHz")


def test_cpuinfo_absent_values():
    assert compare_cpb.parse_cpuinfo_mhz("flags\t: fpu\n") is None
    assert compare_cpb.parse_cpuinfo_model("") is None


def test_read_cpu_mhz_rejects_invalid_flag_values():
    for value in (0.0, -1.0, float("nan"), float("inf"), float("-inf")):
        with pytest.raises(compare_cpb.FatalError):
            compare_cpb.read_cpu_mhz(value)


def _git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _committed_git_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.name", "Animagus Test")
    _git(repo, "config", "user.email", "animagus@example.invalid")
    _git(repo, "config", "core.autocrlf", "false")
    (repo / "tracked.txt").write_bytes(b"first\nsecond\n")
    _git(repo, "add", "tracked.txt")
    _git(repo, "commit", "-m", "fixture")
    return repo


def test_git_provenance_ignores_crlf_only_worktree_changes(tmp_path):
    repo = _committed_git_repo(tmp_path)
    (repo / "tracked.txt").write_bytes(b"first\r\nsecond\r\n")
    assert compare_cpb.git_provenance(repo)["dirty"] is False


def test_git_provenance_detects_substantive_unstaged_change(tmp_path):
    repo = _committed_git_repo(tmp_path)
    (repo / "tracked.txt").write_bytes(b"first\nchanged\n")
    assert compare_cpb.git_provenance(repo)["dirty"] is True


def test_git_provenance_detects_staged_change(tmp_path):
    repo = _committed_git_repo(tmp_path)
    (repo / "tracked.txt").write_bytes(b"first\nstaged\n")
    _git(repo, "add", "tracked.txt")
    assert compare_cpb.git_provenance(repo)["dirty"] is True


def test_git_provenance_detects_untracked_file(tmp_path):
    repo = _committed_git_repo(tmp_path)
    (repo / "untracked.txt").write_text("new\n")
    assert compare_cpb.git_provenance(repo)["dirty"] is True


@pytest.mark.skipif(shutil.which("meson") is None,
                    reason="Meson is unavailable on this host")
def test_build_repo_reconfigures_preexisting_debug_tree_as_release(tmp_path):
    source = tmp_path / "meson-fixture"
    source.mkdir()
    (source / "meson.build").write_text(
        "project('fixture', 'c')\nexecutable('fixture', 'fixture.c')\n")
    (source / "fixture.c").write_text("int main(void) { return 0; }\n")
    compare_cpb.run_command(
        ["meson", "setup", "build", "--buildtype=debug"], cwd=source)

    compare_cpb.build_repo(source, Path("build"), [])

    assert compare_cpb.effective_buildtype(source / "build") == "release"


def test_release_buildtype_validation_rejects_debug_and_unknown():
    for buildtype in ("debug", None):
        repos = {"animagus": {"effective_buildtype": buildtype}}
        with pytest.raises(compare_cpb.FatalError):
            compare_cpb.validate_release_buildtypes(repos)


def make_row(tool, algorithm, impl, operation, bufsize, kbps):
    return {"tool": tool, "algorithm": algorithm, "impl": impl,
            "operation": operation, "bufsize": bufsize,
            "kb_per_second": kbps, "bytes": None, "nanoseconds": None,
            "printed_cpb": None, "cpb": None}


def full_rows(bufsizes=(512, 4096)):
    """A complete archive covering every TABLE_SPEC row.

    AES-256-XTS is split across tools, mirroring what the pristine
    binaries actually print (see the comment on TABLE_SPEC): hctr2 never
    has a generic XTS row, and adiantum never has an accelerated one.
    """
    rows = []
    for bufsize in bufsizes:
        for operation in ("encryption", "decryption"):
            rows.append(make_row("animagus", "AES-256-Animagus", "portable",
                                 operation, bufsize, 1000))
            rows.append(make_row("animagus", "AES-256-Animagus", "hardware",
                                 operation, bufsize, 2000))
            rows.append(make_row("hctr2", "AES-256-HCTR2", "generic",
                                 operation, bufsize, 300))
            rows.append(make_row("hctr2", "AES-256-HCTR2", "simd",
                                 operation, bufsize, 3000))
            rows.append(make_row("hctr2", "AES-256-XTS", "simd",
                                 operation, bufsize, 3000))
            rows.append(make_row("adiantum", "Adiantum-XChaCha12-AES",
                                 "generic", operation, bufsize, 400))
            rows.append(make_row("adiantum", "Adiantum-XChaCha12-AES",
                                 "SSE2", operation, bufsize, 4000))
            rows.append(make_row("tet", "AES-256-TET", "generic",
                                 operation, bufsize, 500))
            rows.append(make_row("tet", "AES-256-TET", "simd",
                                 operation, bufsize, 5000))
            rows.append(make_row("tet", "AES-256-HEH", "generic",
                                 operation, bufsize, 600))
            rows.append(make_row("tet", "AES-256-HEH", "simd",
                                 operation, bufsize, 6000))
            rows.append(make_row("adiantum", "AES-256-XTS", "generic",
                                 operation, bufsize, 300))
    return rows


def test_select_rows_fixed_order():
    # AES-256-XTS is sourced from two different tools: adiantum supplies
    # the generic row (its XTS SIMD path is ARM-only) and hctr2 supplies
    # the accelerated row (its XTS has no generic path at all) -- see the
    # comment on TABLE_SPEC.
    table = compare_cpb.select_table_rows(full_rows(), [512, 4096])
    assert [(entry["algorithm"], entry["impl"]) for entry in table] == [
        ("AES-256-Animagus", "portable"),
        ("AES-256-Animagus", "hardware"),
        ("AES-256-HCTR2", "generic"),
        ("AES-256-HCTR2", "simd"),
        ("Adiantum-XChaCha12-AES", "generic"),
        ("Adiantum-XChaCha12-AES", "SSE2"),
        ("AES-256-TET", "generic"),
        ("AES-256-TET", "simd"),
        ("AES-256-HEH", "generic"),
        ("AES-256-HEH", "simd"),
        ("AES-256-XTS", "generic"),
        ("AES-256-XTS", "simd"),
    ]
    first = table[0]
    assert set(first["cells"]) == {
        (512, "encryption"), (512, "decryption"),
        (4096, "encryption"), (4096, "decryption")}


def test_accelerated_picks_fastest_non_generic_at_largest_bufsize():
    rows = full_rows()
    # A second non-generic impl, fastest at the largest bufsize but slowest
    # at the smallest: it must be chosen, and used for every bufsize.
    for operation in ("encryption", "decryption"):
        rows.append(make_row("hctr2", "AES-256-HCTR2", "avx", operation,
                             4096, 9999))
        rows.append(make_row("hctr2", "AES-256-HCTR2", "avx", operation,
                             512, 1))
    table = compare_cpb.select_table_rows(rows, [512, 4096])
    assert table[3]["impl"] == "avx"
    assert table[3]["cells"][(512, "encryption")]["kb_per_second"] == 1


def test_missing_rows_error_lists_names():
    rows = [row for row in full_rows()
            if not (row["algorithm"] == "AES-256-XTS" and
                    row["impl"] == "simd" and
                    row["operation"] == "decryption" and
                    row["bufsize"] == 512)]
    with pytest.raises(compare_cpb.MissingRowsError) as excinfo:
        compare_cpb.select_table_rows(rows, [512, 4096])
    assert "AES-256-XTS (simd) decryption at 512 B" in str(excinfo.value)
    assert excinfo.value.missing == ["AES-256-XTS (simd) decryption at 512 B"]


def test_missing_accelerated_impl_reported():
    rows = [row for row in full_rows()
            if not (row["tool"] == "adiantum" and row["impl"] != "generic")]
    with pytest.raises(compare_cpb.MissingRowsError) as excinfo:
        compare_cpb.select_table_rows(rows, [512, 4096])
    assert "Adiantum-XChaCha12-AES accelerated" in str(excinfo.value)


def make_meta():
    return {
        "generated_utc": "2026-08-10T12:00:00Z",
        "repos": {
            "animagus": {"commit": "0123456789abcdef0123456789abcdef01234567",
                         "dirty": True},
            "hctr2": {"commit": "89abcdef0123456789abcdef0123456789abcdef",
                      "dirty": False},
            "adiantum": {"commit": None, "dirty": None},
        },
        "cpu_model": "Intel(R) Core(TM) i7-8700 CPU @ 3.20GHz",
        "cpu_mhz": 3192.0,
        "cpu_mhz_source": "cpuinfo",
        "ntries": 25,
    }


def rows_with_cpb(bufsizes=(512, 4096)):
    rows = full_rows(bufsizes)
    for index, row in enumerate(rows):
        row["cpb"] = 10.0 + index * 0.125
    return rows


def test_markdown_structure_and_two_decimals():
    table = compare_cpb.select_table_rows(rows_with_cpb(), [512, 4096])
    text = compare_cpb.render_markdown(table, [512, 4096], "cpb",
                                       make_meta())
    lines = text.splitlines()
    assert "| Algorithm | Impl | 512 B enc/dec | 4096 B enc/dec |" in lines
    data_lines = [line for line in lines
                  if line.startswith("| AES") or
                  line.startswith("| Adiantum")]
    assert len(data_lines) == 12
    assert re.search(r"\| \d+\.\d{2} / \d+\.\d{2} \|", text)
    assert "3192 MHz (cpuinfo)" in text
    assert "best of 25 trials" in text


def test_markdown_generalizes_bufsize_columns():
    bufsizes = [512, 1024, 4096]
    table = compare_cpb.select_table_rows(rows_with_cpb(bufsizes), bufsizes)
    text = compare_cpb.render_markdown(table, bufsizes, "cpb", make_meta())
    assert "512 B enc/dec | 1024 B enc/dec | 4096 B enc/dec" in text


def test_latex_structure():
    table = compare_cpb.select_table_rows(rows_with_cpb(), [512, 4096])
    text = compare_cpb.render_latex(table, [512, 4096], "cpb", make_meta())
    assert "\\begin{tabular}{llrrrr}" in text
    assert "\\multicolumn{2}{c}{512 B}" in text
    assert "\\multicolumn{2}{c}{4096 B}" in text
    assert "\\cmidrule(lr){3-4} \\cmidrule(lr){5-6}" in text
    assert "\\toprule" in text
    assert "\\midrule" in text
    assert "\\bottomrule" in text
    assert "% Generated by benchmark/compare_cpb.py on 2026-08-10" in text
    assert "animagus 0123456789ab dirty" in text
    assert "hctr2 89abcdef0123," in text or "hctr2 89abcdef0123 " in text
    assert "adiantum unknown" in text
    assert "%%" not in text
    assert "Algorithm & Impl. & Enc. & Dec. & Enc. & Dec. \\\\" in text


def test_latex_generalizes_columns():
    bufsizes = [512, 1024, 4096]
    table = compare_cpb.select_table_rows(rows_with_cpb(bufsizes), bufsizes)
    text = compare_cpb.render_latex(table, bufsizes, "cpb", make_meta())
    assert "\\begin{tabular}{llrrrrrr}" in text
    assert ("\\cmidrule(lr){3-4} \\cmidrule(lr){5-6} "
            "\\cmidrule(lr){7-8}") in text


def test_paper_latex_structure():
    table = compare_cpb.select_table_rows(rows_with_cpb(), [512, 4096])
    meta = make_meta()
    meta["notes"] = ["extra caveat line"]
    text = compare_cpb.render_paper_latex(table, [512, 4096], "cpb", meta)
    assert "\\begin{table}[t]" in text
    assert "\\caption{" in text
    assert "\\label{tab:cpb-comparison}" in text
    assert "\\begin{tabular}{llrrrr}" in text
    assert "\\end{table}" in text
    assert "animagus 0123456789ab dirty" in text
    assert "% extra caveat line" in text
    assert "nominal /proc/cpuinfo" in text
    assert "%%" not in text
    body = text.split("\\begin{table}", 1)[1]
    assert "% Generated" not in body


def test_paper_caption_does_not_claim_generic_code_is_constant_time():
    table = compare_cpb.select_table_rows(rows_with_cpb(), [512, 4096])
    text = compare_cpb.render_paper_latex(
        table, [512, 4096], "cpb", make_meta())
    assert "constant-time C" not in text
    assert "portable/generic C" in text


def test_kbps_fallback_renders_integers():
    meta = make_meta()
    meta["cpu_mhz"] = None
    meta["cpu_mhz_source"] = "unavailable"
    table = compare_cpb.select_table_rows(full_rows(), [512, 4096])
    text = compare_cpb.render_markdown(table, [512, 4096], "kbps", meta)
    assert "KB/s" in text
    assert "CPU frequency unavailable" in text
    assert "1000 / 1000" in text
    latex = compare_cpb.render_latex(table, [512, 4096], "kbps", meta)
    assert "frequency unavailable" in latex or \
        "CPU frequency unavailable" in latex
    assert "1000 & 1000" in latex
