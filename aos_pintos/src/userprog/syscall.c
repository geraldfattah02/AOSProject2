#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/block.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <string.h>

static void syscall_handler (struct intr_frame *);

void syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void *validate_user_pointer(void *user_ptr)
{
  if (user_ptr == NULL) return NULL;              // Pointer is NULL
  if (is_kernel_vaddr (user_ptr)) return NULL;    // Pointer to kernel virtual address space

  struct thread *t = thread_current ();
  return pagedir_get_page (t->pagedir, user_ptr); // Return kernel virtual address, or NULL if unmapped
}

static void syscall_handler (struct intr_frame *f)
{
  printf ("system call!\n");
  int syscall_id = *((int*) f->esp);
  printf ("system call %d!\n", syscall_id);

  switch (syscall_id) {
    case SYS_WRITE:
      handle_write(f->esp);
      return;
    default:
      printf ("system call %d!\n", syscall_id);
      thread_exit ();
  }
}

void handle_write(void *stack)
{
  int fd = *((int*)stack+1);
  char *buffer = *((int*)stack+2);
  int size = *((int*)stack+3);
  if (fd == 1)
  {
    putbuf (buffer, size);
  }
  else
  {
    printf ("Unknown fd %d!\n", fd);
  }
}
  