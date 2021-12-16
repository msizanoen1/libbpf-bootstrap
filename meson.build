project('bpf_programs', 'c', version: '0.0.1')

if get_option('bpf-arch') == ''
  error('bpf-arch option is required')
endif

libbpf = dependency('libbpf', static : get_option('libbpf-static'))

bpfcc = find_program(get_option('bpf-cc'), native : true, required : true)
bpfstrip = find_program(get_option('bpf-strip'), native : true, required : true)
bpftool = find_program('bpftool', native : true, required : true)
python3 = import('python').find_installation('python3')

sysinc = find_program('clang_sys_inc.sh')

bpfcc_system_inc_cmd = run_command(sysinc, env : {'CLANG': bpfcc.full_path()})

if bpfcc_system_inc_cmd.returncode() != 0
  error('your build environment is fucked')
endif

bpfcc_system_inc_flags = bpfcc_system_inc_cmd.stdout().split()

bpfcc_cmd = [
  bpfcc,
  '-Wall', '-Wextra', '-Wno-unused-parameter',
  '-target', 'bpf',
  '-c', '-o', '@OUTPUT@', '@INPUT@',
  '-g', '-O3',
  '-gno-inline-line-tables',
  '-D__TARGET_ARCH_' + get_option('bpf-arch'),
  '-I', meson.current_source_dir() / 'vmlinux',
  '-I', libbpf.get_variable(pkgconfig : 'includedir'),
  '-MD',
  '-MQ', '@OUTPUT@',
  '-MF', '@OUTPUT@.d',
] + bpfcc_system_inc_flags

subdir('src')
