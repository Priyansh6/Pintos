#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdint.h>
struct syscall {
    uint32_t (*handler) (void *args[]);
    int argc;
};

void syscall_init (void);

#endif /* userprog/syscall.h */
