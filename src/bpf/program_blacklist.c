// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define NAME_BUF_SIZE 128

SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_check_security,
		struct linux_binprm *bprm) {
	char name[NAME_BUF_SIZE] = { 0 };
	const unsigned char *kname = BPF_CORE_READ(bprm, file, f_path.dentry, d_name.name);
	int err;
	if ((err = bpf_probe_read_kernel(name, NAME_BUF_SIZE - 1, kname)) < 0)
		bpf_printk("bpf_probe_read_kernel(%p): %d\n", kname, err);
	bool cancel = false;
	bool block = false;
#include "evil_list.c.inc"
	
	if (cancel) {
		bpf_printk("Cancelled unwanted right-wing software: %s\n", name);
		return -ECANCELED;
	}

	if (block) {
		bpf_printk("Blocked potentially unwanted/harmful software: %s\n", name);
		return -EPERM;
	}

	return 0;
}
