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
#include "program_blacklist.skel.h"
#include "protected_process.skel.h"
#include "protected_process_common.h"
#include "program_blacklist_events.h"

static struct env {
	bool verbose;
	bool protect_current_process;
	long min_duration_ms;
} env;

const char *argp_program_version = "program_blacklist 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] = "BPF program_blacklist demo application.\n"
				"\n"
				"USAGE: ./program_blacklist [-vp]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "protect", 'p', NULL, 0,
	  "Launch program_blacklist as protected process" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'p':
		env.protect_current_process = true;
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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
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

int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *ev = data;
	printf("program_blacklist: process %d (%.16s) is attempting to execute unauthorized program: %.16s\n",
	       ev->pid, ev->comm, ev->exec);
	return 0;
}

int main(int argc, char **argv)
{
	struct program_blacklist_bpf *skel;
	struct protected_process_bpf *pp = NULL;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.protect_current_process) {
		err = protected_process_init();
		if (err)
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
	skel = program_blacklist_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = program_blacklist_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	struct ring_buffer *rb = ring_buffer__new(
		bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = program_blacklist_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Protect blacklisting */
	if (env.protect_current_process) {
		pp = protect_current_process();
		if (!pp) {
			fprintf(stderr, "Failed to protect current process\n");
			goto cleanup;
		}
		err = ring_buffer__add(rb, bpf_map__fd(pp->maps.events),
				       pp_handle_event, NULL);
		if (err) {
			fprintf(stderr,
				"Failed to register protected process event callback\n");
			goto cleanup;
		}
	}

	while (!exiting) {
		err = ring_buffer__poll(rb, -1);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			goto cleanup;
		}
	}
cleanup:
	/* Clean up */
	program_blacklist_bpf__destroy(skel);
	if (pp)
		protected_process_bpf__destroy(pp);

	return err < 0 ? -err : 0;
}
