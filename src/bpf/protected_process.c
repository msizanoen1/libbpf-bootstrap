// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "protected_process_events.h"

#define SIGKILL 9
#define SIGSTOP 19
#define SIGTSTP 20

#define MAY_EXEC 0x00000001
#define MAY_WRITE 0x00000002
#define MAY_READ 0x00000004
#define MAY_APPEND 0x00000008
#define MAY_ACCESS 0x00000010
#define MAY_OPEN 0x00000020
#define MAY_CHDIR 0x00000040
/* called from RCU mode, don't block */
#define MAY_NOT_BLOCK 0x00000080

/* file is open for reading */
#define FMODE_READ ((fmode_t)0x1)
/* file is open for writing */
#define FMODE_WRITE ((fmode_t)0x2)
/* file is seekable */
#define FMODE_LSEEK ((fmode_t)0x4)
/* file can be accessed using pread */
#define FMODE_PREAD ((fmode_t)0x8)
/* file can be accessed using pwrite */
#define FMODE_PWRITE ((fmode_t)0x10)
/* File is opened for execution with sys_execve / sys_uselib */
#define FMODE_EXEC ((fmode_t)0x20)
/* File is opened with O_NDELAY (only set for block devices) */
#define FMODE_NDELAY ((fmode_t)0x40)
/* File is opened with O_EXCL (only set for block devices) */
#define FMODE_EXCL ((fmode_t)0x80)
/* File is opened using open(.., 3, ..) and is writeable only for ioctls
   (specialy hack for floppy.c) */
#define FMODE_WRITE_IOCTL ((fmode_t)0x100)
/* 32bit hashes as llseek() offset (for directories) */
#define FMODE_32BITHASH ((fmode_t)0x200)
/* 64bit hashes as llseek() offset (for directories) */
#define FMODE_64BITHASH ((fmode_t)0x400)

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4 * 1024 * 1024);
	__type(key, pid_t);
	__type(value, u8);
} protected_processes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4 * 1024 * 1024);
	__type(key, u32);
	__type(value, u8);
} protected_maps SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4 * 1024 * 1024);
	__type(key, pid_t);
	__type(value, u8);
} cgroup_deny_once SEC(".maps");

const struct file_system_type *const volatile cgroup2_fs_type_ptr;
const volatile int cgroup2_protect_inode;
const volatile int cgroup2_freeze_inode;
const volatile int cgroup2_kill_inode;

static const __u8 map_placeholder = 0xff;

__attribute__((always_inline)) static inline pid_t getpid()
{
	return bpf_get_current_pid_tgid() >> 32;
}

__attribute__((always_inline)) static inline pid_t gettid()
{
	return bpf_get_current_pid_tgid() & 0xffffffff;
}

__attribute__((always_inline)) static inline void log_ev(struct event *ev)
{
	ev->pid = getpid();
	ev->uid = bpf_get_current_uid_gid() & 0xffffffff;
	bpf_get_current_comm(ev->comm, sizeof(ev->comm));
	bpf_ringbuf_output(&events, ev, sizeof(*ev), 0);
}

__attribute__((always_inline)) static inline bool is_protected(pid_t tid)
{
	return !!bpf_map_lookup_elem(&protected_processes, &tid);
}

__attribute__((always_inline)) static inline bool is_current_protected()
{
	return is_protected(gettid());
}

__attribute__((always_inline)) static inline void protect(pid_t tid)
{
	bpf_map_update_elem(&protected_processes, &tid, &map_placeholder,
			    BPF_ANY);
}

__attribute__((always_inline)) static inline void unprotect(pid_t tid)
{
	bpf_map_delete_elem(&protected_processes, &tid);
}

__attribute__((always_inline)) static inline void unprotect_current()
{
	unprotect(gettid());
}

SEC("lsm/locked_down")
int BPF_PROG(locked_down, enum lockdown_reason what)
{
	if (!is_current_protected()) {
		struct event ev = {
			.type = KERNEL_LOCKDOWN,
			.lockdown_reason = (int)what,
		};
		log_ev(&ev);
		return -EPERM;
	}
	return 0;
}

SEC("lsm/bpf_map")
int BPF_PROG(bpf_map, struct bpf_map *map, fmode_t fmode)
{
	u32 map_id = BPF_CORE_READ(map, id);
	if ((fmode & FMODE_WRITE) &&
	    bpf_map_lookup_elem(&protected_maps, &map_id) &&
	    !is_current_protected()) {
		struct event ev = { .type = BPF_MAP_TAMPER };
		log_ev(&ev);
		return -EPERM;
	}
	return 0;
}

SEC("lsm/task_kill")
int BPF_PROG(task_kill, struct task_struct *p, struct kernel_siginfo *info,
	     int sig, const struct cred *cred)
{
	pid_t target_pid = BPF_CORE_READ(p, tgid);
	if (is_protected(target_pid) && !is_current_protected()) {
		struct event ev = { .type = TASK_KILL };
		log_ev(&ev);
		return -EPERM;
	}
	return 0;
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(ptrace_access_check, struct task_struct *child, int mode)
{
	pid_t target_pid = BPF_CORE_READ(child, tgid);
	if (is_protected(target_pid) && !is_current_protected()) {
		struct event ev = {
			.type = PTRACE_ATTEMPT,
			.ptrace_mode = mode,
		};
		log_ev(&ev);
		return -EPERM;
	}
	return 0;
}

SEC("lsm/inode_permission")
int BPF_PROG(inode_permission, struct inode *inode, int mask)
{
	if (BPF_CORE_READ(inode, i_sb, s_type) == cgroup2_fs_type_ptr) {
		int ino = BPF_CORE_READ(inode, i_ino);
		if (ino == cgroup2_freeze_inode) {
			struct event ev = { .type = CGROUP_FREEZE };
			log_ev(&ev);
			return -EPERM;
		}
		if (ino == cgroup2_kill_inode) {
			struct event ev = { .type = CGROUP_KILL };
			log_ev(&ev);
			return -EPERM;
		}
		pid_t pid = gettid();
		if (bpf_map_lookup_elem(&cgroup_deny_once, &pid)) {
			bpf_map_delete_elem(&cgroup_deny_once, &pid);
			return -EPERM;
		}
	}
	return 0;
}

#define NAME_BUF_SIZE 128

SEC("fexit/kernel_clone")
int BPF_PROG(kernel_clone, struct kernel_clone_args *args, pid_t dpid)
{
	if (is_current_protected())
		protect(dpid);
	return 0;
}

SEC("fentry/do_exit")
int BPF_PROG(do_exit, long code)
{
	unprotect_current();
	return 0;
}

SEC("fentry/cgroup_attach_permissions")
int BPF_PROG(cgroup_attach_permissions, struct cgroup *src_cgrp,
	     struct cgroup *dst_cgrp, struct super_block *sb, bool threadgroup)
{
	if ((int)BPF_CORE_READ(src_cgrp, kn, id) == cgroup2_protect_inode) {
		pid_t pid = gettid();
		bpf_map_update_elem(&cgroup_deny_once, &pid, &map_placeholder,
				    BPF_ANY);
		struct event ev = { .type = CGROUP_MIGRATE };
		log_ev(&ev);
	}
	return 0;
}
