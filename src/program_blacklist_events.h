#ifndef __program_blacklist_events__
#define __program_blacklist_events__

#define TASK_COMM_LEN 16

struct event {
    char comm[TASK_COMM_LEN];
    char exec[TASK_COMM_LEN];
    pid_t pid;
};

#endif