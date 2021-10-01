// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "program_blacklist_events.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} events SEC(".maps");

#define NAME_BUF_SIZE 128

SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_check_security, struct linux_binprm *bprm)
{
	char name[NAME_BUF_SIZE] = { 0 };
	struct event ev = {};
	const unsigned char *kname =
		BPF_CORE_READ(bprm, file, f_path.dentry, d_name.name);
	int err = bpf_probe_read_kernel_str(name, NAME_BUF_SIZE - 1, kname);
	if (err < 0)
		bpf_printk("bpf_probe_read_kernel(%p): %d\n", kname, err);
	bool cancel = false;
	bool block = false;
#include "evil_list.c.inc"

	if (cancel || block) {
		bpf_get_current_comm(ev.comm, sizeof(ev.comm));
		ev.pid = (pid_t)(bpf_get_current_pid_tgid() >> 32);
		__builtin_memcpy(ev.exec, name, TASK_COMM_LEN);
		bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
	}

	if (cancel) {
		return -ECANCELED;
	}

	if (block) {
		return -EPERM;
	}

	return 0;
}
