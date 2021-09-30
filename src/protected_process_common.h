#pragma once

#include "protected_process.skel.h"

extern bool pplib_verbose;

int protected_process_init();
void protected_process_rodata(struct protected_process_bpf *);
int protected_process_setup(struct protected_process_bpf *);