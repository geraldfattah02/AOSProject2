#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/block.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <string.h>
#include "threads/vaddr.h"
#include "process.h"

static void syscall_handler (struct intr_frame *);

void syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void *validate_user_pointer (void *user_ptr)
{
  if (user_ptr == NULL)
    return NULL; // Pointer is NULL
  if (is_kernel_vaddr (user_ptr))
    return NULL; // Pointer to kernel virtual address space

  struct thread *t = thread_current ();
  return pagedir_get_page (
      t->pagedir,
      user_ptr); // Return kernel virtual address, or NULL if unmapped
}

static void set_exit_code (struct thread *t, int code)
{
  if (t->parent_record != NULL)
    t->parent_record->exit_code = code;
}

tid_t exec (const char *cmd_line) {
  if (validate_user_pointer(cmd_line) == NULL) {
    return -1;
  }
  tid_t child_pid = process_execute(cmd_line);
  struct child_thread *child_record = get_child_record(child_pid);

  if (child_record == NULL) {
      return -1;
  } else {
      sema_down(&child_record->wait_child);
      if (child_record->loaded_successfully) {
          return child_pid;
      } else {
          return -1;
      }
  }
  return child_pid;
}

static void syscall_handler (struct intr_frame *f)
{
  // Check if esp is valid, and the arguments (at most 3) are not in kernel
  // space
  if (validate_user_pointer (f->esp) == NULL ||
      is_kernel_vaddr ((int *) f->esp + 3) || (uint32_t) f->esp % 4 != 0)
    {
      set_exit_code (thread_current (), -1);
      thread_exit ();
    }
  // printf ("system call %p\n", f->esp);
  int syscall_id = *((int *) f->esp);
  // printf ("system call %d!\n", syscall_id);

  switch (syscall_id)
    {
      case SYS_WRITE:
        handle_write (f->esp);
        return;
      case SYS_EXIT:
        // printf("Calling SYS_EXIT\n");
        //  TODO: handle exit code, files
        set_exit_code (thread_current (), *((int *) f->esp + 1));
        thread_exit ();
      case SYS_EXEC: {
        char *cmd_line = *((char **) f->esp + 1); // pointer to first argument
        f->eax = exec (cmd_line);
      }
      default:
        printf ("system call %d!\n", syscall_id);
        thread_exit ();
    }
}

void handle_write (void *stack)
{
  int fd = *((int *) stack + 1);
  char *buffer = *((int *) stack + 2);
  int size = *((int *) stack + 3);
  if (fd == 1)
    {
      putbuf (buffer, size);
    }
  else
    {
      printf ("Unknown fd %d!\n", fd);
    }
}
