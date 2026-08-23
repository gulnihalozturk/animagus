# Third-party sources

Files in `third_party/linux-kernel/` are Linux-kernel-derived AES sources,
copied byte-for-byte from an upstream userspace adaptation of the kernel's
AES implementation. The table records every copied path, its upstream
identity, governing license notice, and the SHA-256 verified when it was
imported.

The complete copied subtree is byte-identical to the corresponding paths in
[google/hctr2](https://github.com/google/hctr2/tree/0b0b5375b7aa866c6dfc55cd3f11bb07d2b7aa46/third_party/linux-kernel)
at commit `0b0b5375b7aa866c6dfc55cd3f11bb07d2b7aa46`, verified locally on
2026-08-23. That repository snapshot is the exact userspace-adaptation source;
the per-file identities below describe the underlying Linux sources retained
by that snapshot.

| Copied path | Upstream provenance | Governing license | SHA-256 |
| --- | --- | --- | --- |
| `third_party/linux-kernel/COPYING` | GNU GPL version 2 license text accompanying the Linux-kernel-derived subtree | GPLv2 | `a1f66531b3c0b1faf49ac6272698fa6086911faffb9bf032d71299517ac0df6c` |
| `third_party/linux-kernel/LICENSE` | Upstream summary notice for the Linux-kernel-derived subtree | GPLv2 | `5ff1c6a82e85b73080d861032a109f7926b7d4729d0affe37408ba4103fa224d` |
| `third_party/linux-kernel/aes_linux.h` | Linux common AES constants and context definitions | SPDX `GPL-2.0` | `b4d286bf309cf44b2fbf6e0174a1ec58554666ccc950d70e8d83cef529a57147` |
| `third_party/linux-kernel/aes_ti.c` | Linux scalar fixed-time AES core transform, copyright 2017 Linaro Ltd | GPL version 2 as published | `07dd547e37a3d850b6cc2f135f5118932a5b3bdf803319c40809f460eb84da55` |
| `third_party/linux-kernel/aarch64/aes-ce.S` | Linux `arch/arm64/crypto` AES cipher for ARMv8 Crypto Extensions, copyright 2013-2017 Linaro Ltd | SPDX `GPL-2.0-only` | `3ee0965d76eb22ca7b736c18fb01dc58281cfa83bf944c0f947f3c13d517545d` |
| `third_party/linux-kernel/aarch64/aes-modes.S` | Linux `arch/arm64/crypto` AES chaining-mode wrappers, copyright 2013-2017 Linaro Ltd | SPDX `GPL-2.0-only` | `36d725fcc5e85b2b3e39f09a7731561fd71a362e62aa25b17ef87822f70e839a` |
| `third_party/linux-kernel/x86_64/aesni-intel_asm.S` | Linux x86 AES-NI implementation originating with Intel contributors | SPDX `GPL-2.0-or-later` | `f73c7d6ff4a51ad2ab675256a94ecaa05cefa08a7006b7c02f5e9f543860219a` |

The copied source files retain their own headers and notices. The exact
GPLv2 text is in `third_party/linux-kernel/COPYING`; the shorter subtree notice
is in `third_party/linux-kernel/LICENSE`.

## Licensing boundary

Files authored for this repository are covered by the root MIT license unless
they carry a separate notice. That MIT grant does not relicense the copied
Linux sources. `third_party/linux-kernel/aes_ti.c` supplies scalar AES and is
compiled into `libanimagus` on every architecture, so even a build that selects
`ANIMAGUS_BACKEND_PORTABLE` includes GPLv2-derived code. x86_64 builds also
include the GPL-2.0-or-later AES-NI file; AArch64 builds include the two
GPL-2.0-only assembly files.

Consequently, a combined static library or executable is not a purely MIT
artifact. Anyone distributing combined binaries or modified copied sources
must satisfy the applicable GPL terms and preserve the MIT notices for the
repository's MIT-covered portions.

`src/asm_common.h` is separately adapted from Google's MIT-licensed
cipherbench support header and retains its MIT notice. The benchmark sources
identify their MIT-licensed adaptations (Copyright 2018 Google LLC) in their
file headers; neither group is part of the GPL third-party subtree.
