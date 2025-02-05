#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM	  1
#define PROT_EXEC 0x4
#define NAME_MAX  255

SEC("lsm/mmap_file")
int BPF_PROG(libdecor_lsm_mmap_file, struct file *file, unsigned long reqprot, unsigned long prot,
	     unsigned long flags)
{
	char name_buf[NAME_MAX + 1];

	if (!(prot & PROT_EXEC))
		return 0;

	if (bpf_probe_read_kernel_str(name_buf, sizeof(name_buf),
				      BPF_CORE_READ(file, f_path.dentry, d_name.name)) < 0)
		return 0;

	if (!__builtin_strcmp(name_buf, "libdecor-gtk.so"))
		return -EPERM;

	return 0;
}
