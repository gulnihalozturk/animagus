project('animagus', 'c',
  version: '0.1.0',
  default_options: ['c_std=c11', 'warning_level=3'])

cc = meson.get_compiler('c')
conf = configuration_data()
conf.set10('SYMBOLS_HAVE_UNDERSCORE_PREFIX',
  cc.symbols_have_underscore_prefix())
configure_file(output: 'cbconfig.h', configuration: conf)

public_inc = include_directories('include')
root_inc = include_directories('src', 'third_party/linux-kernel')
build_inc = include_directories('.')
local_c_args = ['-Wall', '-Wextra', '-Wpedantic', '-Werror',
                '-fno-strict-aliasing', '-fwrapv']
arch_c_args = []

animagus_sources = [
  'src/animagus.c',
  'src/util.c',
  'src/aes.c',
  'src/animagus_ctr.c',
  'src/sha3.c',
  'src/hmac_sha3.c',
  'third_party/linux-kernel/aes_ti.c',
]

if host_machine.cpu_family() == 'x86_64'
  animagus_sources += 'third_party/linux-kernel/x86_64/aesni-intel_asm.S'
elif host_machine.cpu_family() == 'aarch64'
  animagus_sources += 'third_party/linux-kernel/aarch64/aes-ce.S'
  # The unchanged Linux assembly uses GNU named variadic preprocessor macros.
  arch_c_args += '-Wno-variadic-macros'
endif

libanimagus = static_library('animagus', animagus_sources,
  include_directories: [public_inc, root_inc, build_inc],
  c_args: local_c_args + arch_c_args)

animagus_dep = declare_dependency(
  include_directories: public_inc,
  link_with: libanimagus)

subdir('tests')
subdir('benchmark')
