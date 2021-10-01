bpf_programs = {
  'program_blacklist': [evil_list],
  'protected_process': [],
}

bpf_programs_d = {}

foreach prog, pdeps : bpf_programs
  prog_c = prog + '.c'
  prog_o = prog + '.o'
  prog_h = prog + '.skel.h'
  flags = []
  deps = []
  foreach dep : pdeps
    flags += ['-I', dep.get('include')]
    deps += [dep.get('dep')]
  endforeach
  target = custom_target(prog_o,
    output : prog_o,
    input : prog_c,
    depends : deps,
    depfile : '@OUTPUT@.d',
    command : bpfcc_cmd + flags)
  header = custom_target(prog_h,
    output : prog_h,
    input : target,
    capture : true,
    command : [bpftool, 'gen', 'skeleton', '@INPUT@', 'name', prog + '_bpf'])
  dependency = declare_dependency(sources : header, include_directories : '.')
  bpf_programs_d += { prog : dependency }
endforeach

protected_process = bpf_programs_d.get('protected_process')
program_blacklist = bpf_programs_d.get('program_blacklist')
