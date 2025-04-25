#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include "threads/thread.h"

void syscall_init (void);

void free_thread_resources (struct thread *);

#endif /* userprog/syscall.h */
