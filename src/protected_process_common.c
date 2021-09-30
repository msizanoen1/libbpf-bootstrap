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
    skel->rodata->cgroup2_fs_type_ptr = (struct file_system_type *)cgroup2_fs_type;
    skel->rodata->cgroup2_protect_inode = cgroup2_protect_inode;
    skel->rodata->cgroup2_freeze_inode = cgroup2_freeze_inode;
}

int protected_process_setup(struct protected_process_bpf *skel)
{
    int err;
    const static __u8 map_placeholder = 0xff;
    pid_t pid = getpid();
    err = bpf_map_update_elem(bpf_map__fd(skel->maps.protected_processes), &pid, &map_placeholder, BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to register protected process\n");
        return err;
    }

    err = bpf_map_freeze(bpf_map__fd(skel->maps.protected_processes));
    if (err) {
        fprintf(stderr, "Failed to lock down protected processes list\n");
        return err;
    }
    
    err = bpf_map_freeze(bpf_map__fd(skel->maps.cgroup_deny_once));
    if (err) {
        fprintf(stderr, "Failed to lock down cgroup deny once list\n");
        return err;
    }

    return 0;
}