// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */

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

static struct env {
	bool verbose;
	long min_duration_ms;
} env;

const char *argp_program_version = "protected_process 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
"BPF protected_process demo application.\n"
"\n"
"USAGE: ./protected_process [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static uintptr_t cgroup2_fs_type = 0;

static int lookup_kallsyms(void) {
	FILE *kallsyms = fopen("/proc/kallsyms", "r");
	if (!kallsyms) {
		return -errno;
	}
	char *symbol, type;
	uintptr_t address;
	while (fscanf(kallsyms, "%zx %c %ms", &address, &type, &symbol) == 3) {
		if (strcmp(symbol, "cgroup2_fs_type") == 0) {
			fprintf(stderr, "kallsyms: address of %s is %p\n", symbol, (void *)address);
			cgroup2_fs_type = address;
		}
		free(symbol);
	}
	fclose(kallsyms);
	return 0;
}

static int cgroup2_protect_inode = 0;
static int cgroup2_freeze_inode = 0;

static int cgroup2_find(void) {
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
		if (path[0] == '0' && path[1] == ':' && path[2] == ':') { // cgroup2
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
			fprintf(stderr, "cgroup2 located (path = %s, ino = %d, freeze_ino = %d)\n", path + 3, cgroup2_protect_inode, cgroup2_freeze_inode);
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

int main(int argc, char **argv)
{
	struct protected_process_bpf *skel;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

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

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to create BPF maps */
	bump_memlock_rlimit();

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = protected_process_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	skel->rodata->cgroup2_fs_type_ptr = (struct file_system_type *)cgroup2_fs_type;
	skel->rodata->cgroup2_protect_inode = cgroup2_protect_inode;
	skel->rodata->cgroup2_freeze_inode = cgroup2_freeze_inode;

	/* Load & verify BPF programs */
	err = protected_process_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	const static __u8 map_placeholder = 0xff;
	pid_t pid = getpid();
	err = bpf_map_update_elem(bpf_map__fd(skel->maps.protected_processes), &pid, &map_placeholder, BPF_ANY);
	if (err) {
		fprintf(stderr, "Failed to register protected process\n");
		goto cleanup;
	}

	err = bpf_map_freeze(bpf_map__fd(skel->maps.protected_processes));
	if (err) {
		fprintf(stderr, "Failed to lock down protected processes list\n");
		goto cleanup;
	}
	
	err = bpf_map_freeze(bpf_map__fd(skel->maps.cgroup_deny_once));
	if (err) {
		fprintf(stderr, "Failed to lock down cgroup deny once list\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = protected_process_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	system("/bin/bash");
cleanup:
	/* Clean up */
	protected_process_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
