// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <bpf/libbpf.h>
#include "libdecor_lsm.skel.h"

#define _cleanup_(f) __attribute__((cleanup(f)))

static void closep(int *fd)
{
	if (!fd || *fd < 0)
		return;

	close(*fd);
	*fd = -1;
}

static int notify(const char *message)
{
	union sockaddr_union {
		struct sockaddr sa;
		struct sockaddr_un sun;
	} socket_addr = {
		.sun.sun_family = AF_UNIX,
	};
	size_t path_length, message_length;
	_cleanup_(closep) int fd = -1;
	const char *socket_path;

	/* Verify the argument first */
	if (!message)
		return -EINVAL;

	message_length = strlen(message);
	if (message_length == 0)
		return -EINVAL;

	/* If the variable is not set, the protocol is a noop */
	socket_path = getenv("NOTIFY_SOCKET");
	if (!socket_path)
		return 0; /* Not set? Nothing to do */

	/* Only AF_UNIX is supported, with path or abstract sockets */
	if (socket_path[0] != '/' && socket_path[0] != '@')
		return -EAFNOSUPPORT;

	path_length = strlen(socket_path);
	/* Ensure there is room for NUL byte */
	if (path_length >= sizeof(socket_addr.sun.sun_path))
		return -E2BIG;

	memcpy(socket_addr.sun.sun_path, socket_path, path_length);

	/* Support for abstract socket */
	if (socket_addr.sun.sun_path[0] == '@')
		socket_addr.sun.sun_path[0] = 0;

	fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	if (connect(fd, &socket_addr.sa, offsetof(struct sockaddr_un, sun_path) + path_length) != 0)
		return -errno;

	ssize_t written = write(fd, message, message_length);
	if (written != (ssize_t)message_length)
		return written < 0 ? -errno : -EPROTO;

	return 1; /* Notified! */
}

static int notify_ready(void)
{
	return notify("READY=1");
}

/* Notice: Ensure your kernel version is 5.7 or higher, BTF (BPF Type Format) is enabled, 
 * and the file '/sys/kernel/security/lsm' includes 'bpf'.
 */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct libdecor_lsm_bpf *skel;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open, load, and verify BPF application */
	skel = libdecor_lsm_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		goto cleanup;
	}

	/* Attach lsm handler */
	err = libdecor_lsm_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	notify_ready();

	for (;;)
		pause();

cleanup:
	libdecor_lsm_bpf__destroy(skel);
	return -err;
}
