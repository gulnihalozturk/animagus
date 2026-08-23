test_aes = executable('test_aes',
  ['test_aes.c', 'test_common.c'],
  include_directories: root_inc,
  dependencies: animagus_dep,
  c_args: local_c_args)

test('aes', test_aes)

test_sha3 = executable('test_sha3',
  ['test_sha3.c', 'test_common.c'],
  include_directories: root_inc,
  dependencies: animagus_dep,
  c_args: local_c_args)

test('sha3', test_sha3)

test_hmac_sha3 = executable('test_hmac_sha3',
  ['test_hmac_sha3.c', 'test_common.c'],
  include_directories: [root_inc,
    include_directories('../test_vectors/converted/cstruct')],
  dependencies: animagus_dep,
  c_args: local_c_args)

test('hmac_sha3', test_hmac_sha3)

test_animagus_ctr = executable('test_animagus_ctr',
  ['test_animagus_ctr.c', 'test_common.c'],
  include_directories: root_inc,
  dependencies: animagus_dep,
  c_args: local_c_args)

test('animagus_ctr', test_animagus_ctr)

test_animagus = executable('test_animagus',
  ['test_animagus.c', 'test_common.c',
   '../test_vectors/converted/cstruct/animagus_testvecs.c'],
  include_directories: [root_inc,
    include_directories('../test_vectors/converted/cstruct')],
  dependencies: animagus_dep,
  c_args: local_c_args)

test('animagus', test_animagus)
