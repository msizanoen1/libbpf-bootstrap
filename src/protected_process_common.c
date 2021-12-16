#define _GNU_SOURCE

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include "protected_process.skel.h"
#include "protected_process_common.h"
#include "protected_process_events.h"

static uintptr_t cgroup2_fs_type = 0;

static int lookup_kallsyms(void)
{
	FILE *kallsyms = fopen("/proc/kallsyms", "r");
	if (!kallsyms) {
		return -errno;
	}
	char *symbol, type;
	uintptr_t address;
	while (fscanf(kallsyms, "%zx %c %ms", &address, &type, &symbol) == 3) {
		if (strcmp(symbol, "cgroup2_fs_type") == 0) {
			fprintf(stderr, "kallsyms: address of %s is %p\n",
				symbol, (void *)address);
			cgroup2_fs_type = address;
		}
		free(symbol);
	}
	fclose(kallsyms);
	return 0;
}

static int cgroup2_protect_inode = -1;
static int cgroup2_freeze_inode = -1;
static int cgroup2_kill_inode = -1;

static int cgroup2_find(void)
{
	int cgroot = open("/sys/fs/cgroup", O_PATH);
	if (cgroot < 0)
		return cgroot;
	FILE *cginf = fopen("/proc/self/cgroup", "r");
	if (!cginf) {
		close(cgroot);
		return -errno;
	}
	char *path = NULL;
	size_t len = 0;
	struct stat st;
	while (getline(&path, &len, cginf) != -1) {
		if (path[0] == '0' && path[1] == ':' &&
		    path[2] == ':') { // cgroup2
			path[strlen(path) - 1] = '\0';
			if (fstatat(cgroot, path + 4, &st, 0)) {
				fclose(cginf);
				close(cgroot);
				return -errno;
			}
			cgroup2_protect_inode = (int)st.st_ino;
			fclose(cginf);
			int fd = openat(cgroot, path + 4, O_PATH);
			if (fd < 0) {
				close(cgroot);
				return fd;
			}
			close(cgroot);
			int err = fstatat(fd, "cgroup.freeze", &st, 0);
			if (err)
				return err;
			cgroup2_freeze_inode = (int)st.st_ino;
			err = fstatat(fd, "cgroup.kill", &st, 0);
			if (!err)
				cgroup2_kill_inode = (int)st.st_ino;
			fprintf(stderr,
				"protected_process: cgroup2 located (path = %s, ino = %d, freeze_ino = %d, kill_ino = %d)\n",
				path + 3, cgroup2_protect_inode,
				cgroup2_freeze_inode, cgroup2_kill_inode);
			return 0;
		}
		free(path);
		path = NULL;
		len = 0;
	}
	fclose(cginf);
	close(cgroot);
	return -ENOENT;
}

int protected_process_init()
{
	int err;
	err = lookup_kallsyms();
	if (err) {
		perror("lookup_kallsyms");
		return err;
	}

	err = cgroup2_find();
	if (err) {
		perror("cgroup2_find");
		return err;
	}

	return 0;
}

void protected_process_rodata(struct protected_process_bpf *skel)
{
	skel->rodata->cgroup2_fs_type_ptr =
		(struct file_system_type *)cgroup2_fs_type;
	skel->rodata->cgroup2_protect_inode = cgroup2_protect_inode;
	skel->rodata->cgroup2_freeze_inode = cgroup2_freeze_inode;
	skel->rodata->cgroup2_kill_inode = cgroup2_kill_inode;
}

int protected_process_setup(struct protected_process_bpf *skel)
{
	struct bpf_map_info info = {};
	uint32_t len = (uint32_t)sizeof(info);
	int err;
	const static __u8 map_placeholder = 0xff;
	pid_t pid = getpid();

	err = bpf_map_update_elem(bpf_map__fd(skel->maps.protected_processes),
				  &pid, &map_placeholder, BPF_ANY);
	if (err)
		return err;

	err = bpf_obj_get_info_by_fd(bpf_map__fd(skel->maps.protected_maps),
				     &info, &len);
	if (err)
		return err;

	err = bpf_map_update_elem(bpf_map__fd(skel->maps.protected_maps),
				  &info.id, &map_placeholder, BPF_ANY);
	if (err)
		return err;

	err = bpf_obj_get_info_by_fd(
		bpf_map__fd(skel->maps.protected_processes), &info, &len);
	if (err)
		return err;

	err = bpf_map_update_elem(bpf_map__fd(skel->maps.protected_maps),
				  &info.id, &map_placeholder, BPF_ANY);
	if (err)
		return err;

	err = bpf_obj_get_info_by_fd(bpf_map__fd(skel->maps.cgroup_deny_once),
				     &info, &len);
	if (err)
		return err;

	err = bpf_map_update_elem(bpf_map__fd(skel->maps.protected_maps),
				  &info.id, &map_placeholder, BPF_ANY);
	if (err)
		return err;

	return 0;
}

struct protected_process_bpf *protect_current_process()
{
	int err;
	struct protected_process_bpf *skel;

	skel = protected_process_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return NULL;
	}

	protected_process_rodata(skel);

	/* Load & verify BPF programs */
	err = protected_process_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = protected_process_setup(skel);
	if (err) {
		goto cleanup;
	}

	/* Attach tracepoints */
	err = protected_process_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	fprintf(stderr, "protected_process: Process is protected\n");

	return skel;
cleanup:
	protected_process_bpf__destroy(skel);
	return NULL;
}

int pp_handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *ev = data;
	printf("protected_process: process %d (%.16s) (uid = %d) attempted to ",
	       (int)ev->pid, ev->comm, (int)ev->uid);
	switch (ev->type) {
	case KERNEL_LOCKDOWN:
		printf("compromise system integrity (lockdown_reason = %d)\n",
		       ev->lockdown_reason);
		break;
	case CGROUP_FREEZE:
		printf("freeze cgroup containing protected process\n");
		break;
	case CGROUP_KILL:
		printf("kill cgroup containing protected process\n");
		break;
	case CGROUP_MIGRATE:
		printf("migrate protected process to another cgroup\n");
		break;
	case PTRACE_ATTEMPT:
		printf("access protected process (ptrace_mode = %d)\n",
		       ev->ptrace_mode);
		break;
	case TASK_KILL:
		printf("kill protected process\n");
		break;
	case BPF_MAP_TAMPER:
		printf("tamper protected BPF maps\n");
		break;
	default:
		printf("perform unknown unauthorized action\n");
	};
	return 0;
}
