project('bpf_programs', 'c', version: '0.0.1')

if get_option('bpf-arch') == ''
  error('bpf-arch option is required')
endif

libbpf = dependency('libbpf')

bpfcc = find_program(get_option('bpf-cc'), native : true, required : true)
bpftool = find_program('bpftool', native : true, required : true)
python3 = import('python').find_installation('python3')

evil_list_generator = meson.current_source_dir() / 'src/evil_list.py'

sysinc = find_program('clang_sys_inc.sh')

bpfcc_system_inc_cmd = run_command(sysinc, env : {'CLANG': bpfcc.full_path()})

if bpfcc_system_inc_cmd.returncode() != 0
  error('your build environment is fucked')
endif

bpfcc_system_inc_flags = bpfcc_system_inc_cmd.stdout().split()

bpfcc_cmd = [
  bpfcc,
  '-target', 'bpf',
  '-c', '-o', '@OUTPUT@', '@INPUT@',
  '-g', '-O3',
  '-D__TARGET_ARCH_' + get_option('bpf-arch'),
  '-I' + meson.current_build_dir(),
  '-I' + meson.current_source_dir() / 'vmlinux',
  '-I' + libbpf.get_variable(pkgconfig : 'includedir'),
  '-MD',
  '-MQ', '@OUTPUT@',
  '-MF', '@OUTPUT@.d',
] + bpfcc_system_inc_flags

evil_list = custom_target('evil_list.c.inc',
  input : 'src/evil_list.yaml',
  output : 'evil_list.c.inc',
  command : [python3, evil_list_generator, '@INPUT@', '@OUTPUT@'])

bpf_programs = {
  'program_blacklist': [evil_list],
  'protected_process': [],
}

bpf_programs_d = {}

foreach prog, deps : bpf_programs
  prog_c = 'src/bpf' / prog + '.c'
  prog_o = prog + '.bpf_o'
  prog_h = prog + '.skel.h'
  target = custom_target(prog_o,
    output : prog_o,
    input : prog_c,
    depends : deps,
    depfile : '@OUTPUT@.d',
    command : bpfcc_cmd)
  header = custom_target(prog_h,
    output : prog_h,
    input : target,
    capture : true,
    command : [bpftool, 'gen', 'skeleton', '@INPUT@', 'name', prog + '_bpf'])
  dependency = declare_dependency(sources : header)
  bpf_programs_d += { prog : dependency }
endforeach

protected_process = bpf_programs_d.get('protected_process')
program_blacklist = bpf_programs_d.get('program_blacklist')

executable('protected_process',
  ['src/protected_process.c', 'src/protected_process_common.c'],
  dependencies : [protected_process, libbpf])

executable('program_blacklist',
  ['src/program_blacklist.c', 'src/protected_process_common.c'],
  dependencies : [
    protected_process,
    program_blacklist,
    libbpf,
  ])
