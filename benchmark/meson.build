animagus_cipherbench = executable('animagus-cipherbench',
  [
    'src/cipherbench.c',
    'src/bench_time.c',
  ],
  include_directories: public_inc,
  dependencies: animagus_dep,
  c_args: local_c_args)

test('animagus-cipherbench-smoke', find_program('sh'),
  args: [
    '-c',
    '''set -eu
output=$("$1" --bufsize=32 --ntries=1 --total-bytes=4096 --key-size=256 --backend=portable)
printf '%s\\n' "$output" | grep -F 'AES-256-Animagus encryption (portable)'
printf '%s\\n' "$output" | grep -F 'AES-256-Animagus decryption (portable)'
printf '%s\\n' "$output" | grep -F 'KB/s'
if abbreviated_output=$("$1" --buf=32 --ntries=1 --total-bytes=4096 --key-size=256 --backend=portable 2>/dev/null); then
  exit 1
fi
test -z "$abbreviated_output"
if abbreviated_output=$("$1" --bufsize=32 --ntries=1 --total-bytes=4096 --key-size=256 --back=portable 2>/dev/null); then
  exit 1
fi
test -z "$abbreviated_output"
''',
    'cipherbench-smoke',
    animagus_cipherbench,
  ])

if meson.can_run_host_binaries()
  output512 = custom_target('output512',
    command: [animagus_cipherbench, '--bufsize=512', '--ntries=25'],
    output: 'output512',
    capture: true)

  output4096 = custom_target('output4096',
    command: [animagus_cipherbench, '--bufsize=4096', '--ntries=25'],
    output: 'output4096',
    capture: true)
endif

benchmark('benchmark', animagus_cipherbench)
