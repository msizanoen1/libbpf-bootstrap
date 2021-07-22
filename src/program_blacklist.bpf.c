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
	if (
		name[0] == 'b' &&
		name[1] == 'r' &&
		name[2] == 'a' &&
		name[3] == 'v' &&
		name[4] == 'e'
	)
		cancel = true;

	if (
		name[0] == 's' &&
		name[1] == 'n' &&
		name[2] == 'a' &&
		name[3] == 'p' &&
		name[4] == 'd' &&
		name[5] == '\0'
	)
		cancel = true;
	
	if (cancel) {
		bpf_printk("Cancelled unwanted right-wing software: %s\n", name);
		return -ECANCELED;
	}

	return 0;
}
