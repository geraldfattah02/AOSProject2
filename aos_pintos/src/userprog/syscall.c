#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/block.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <string.h>
#include "threads/vaddr.h"
#include "userprog/process.h"

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

static void set_exit_code(struct thread *t, int code)
{
  if (t->parent_record != NULL)
    t->parent_record->exit_code = code;
}

static bool has_bad_boundary(char *ptr)
{
  return validate_user_pointer(ptr) == NULL || validate_user_pointer(ptr + 3) == NULL;
}

static void syscall_handler (struct intr_frame *f)
{
  // printf ("system call %p\n", f->esp);
  // printf("mod 4: %d\n", (uint32_t)f->esp % 4);
  // printf("has bad boundary %d\n", has_bad_boundary(f->esp));

  // Check if esp is valid and aligned, and that the arguments (at most 3) are not in kernel space
  if (validate_user_pointer(f->esp) == NULL || is_kernel_vaddr((int*)f->esp + 3) || has_bad_boundary(f->esp))
  {
    set_exit_code (thread_current (), -1);
    thread_exit ();
  }
  int syscall_id = *((int*) f->esp);
  // printf ("system call %d!\n", syscall_id);

  switch (syscall_id) {
    case SYS_HALT:
      shutdown_power_off();
    case SYS_WAIT:
      handle_wait(f->esp);
      return;
    case SYS_WRITE:
      handle_write(f->esp);
      return;
    case SYS_EXIT:
      //printf("Calling SYS_EXIT\n");
      // TODO: handle exit code, files
      set_exit_code (thread_current (), *((int*)f->esp+1));
      thread_exit ();
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

void handle_wait(void *stack)
{
  tid_t tid = *((int*)stack+1);
  return process_wait(tid);
}
  