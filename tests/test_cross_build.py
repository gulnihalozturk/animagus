#!/usr/bin/env python3

import pathlib
import shutil
import subprocess
import tempfile
import textwrap
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class CrossBuildTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("meson"),
                         "Meson is unavailable on this host")
    def test_wrapperless_cross_setup_does_not_run_host_binaries(self):
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = pathlib.Path(directory)
            cross_file = temporary_root / "wrapperless.ini"
            cross_file.write_text(
                textwrap.dedent(
                    """
                    [binaries]
                    c = 'cc'
                    ar = 'ar'
                    strip = 'strip'

                    [host_machine]
                    system = 'linux'
                    cpu_family = 'aarch64'
                    cpu = 'aarch64'
                    endian = 'little'

                    [properties]
                    needs_exe_wrapper = true
                    """
                ),
                encoding="ascii",
            )
            build_dir = temporary_root / "build"
            completed = subprocess.run(
                [
                    "meson",
                    "setup",
                    str(build_dir),
                    str(ROOT),
                    "--cross-file",
                    str(cross_file),
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(
                completed.returncode,
                0,
                msg=(
                    "wrapper-less cross setup failed:\n"
                    f"--- stdout ---\n{completed.stdout}"
                    f"--- stderr ---\n{completed.stderr}"
                ),
            )


if __name__ == "__main__":
    unittest.main()
