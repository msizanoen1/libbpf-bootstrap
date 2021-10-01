evil_list_generator = meson.current_source_dir() / 'evil_list.py'

evil_list_inc = custom_target('evil_list.c.inc',
  input : 'evil_list.yaml',
  output : 'evil_list.c.inc',
  command : [python3, evil_list_generator, '@INPUT@', '@OUTPUT@'])

evil_list = {
  'dep' : evil_list_inc,
  'include': meson.current_build_dir(),
}

bpfcc_cmd += ['-I', meson.current_source_dir()]

subdir('bpf')

pp_common = static_library('protected_process_common',
  'protected_process_common.c',
  dependencies : [protected_process, libbpf])

executable('protected_process',
  'protected_process.c',
  link_with : pp_common,
  dependencies : [protected_process, libbpf])

executable('program_blacklist',
  'program_blacklist.c',
  link_with : pp_common,
  dependencies : [
    protected_process,
    program_blacklist,
    libbpf,
  ])
