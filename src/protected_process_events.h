#ifndef __protected_process_events__
#define __protected_process_events__

#define TASK_COMM_LEN 16

enum event_type {
	KERNEL_LOCKDOWN,
	CGROUP_FREEZE,
	CGROUP_KILL,
	CGROUP_MIGRATE,
	PTRACE_ATTEMPT,
	TASK_KILL,
	BPF_MAP_TAMPER,
};

struct event {
	enum event_type type;
	pid_t pid;
	uid_t uid;
	char comm[TASK_COMM_LEN];
	union {
		int lockdown_reason;
		int ptrace_mode;
	};
};

#endif
