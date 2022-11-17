#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdint.h>
#include "threads/synch.h"
struct syscall {
    uint32_t (*handler) (void *args[]);         /* Function responsible for carrying out system call. */
    int argc;                                   /* Number of arguments we expect to be passed to the system call. */
};

struct lock fs_lock;

void syscall_init (void);
void exit_failure (void);

#endif /* userprog/syscall.h */
