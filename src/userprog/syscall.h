#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdint.h>
#include "lib/stddef.h"
#include "filesys/file.h"

/* Process identifier. */
typedef int pid_t;

void syscall_init (void);

#endif /* userprog/syscall.h */
