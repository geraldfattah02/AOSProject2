#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/block.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <string.h>
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "process.h"
#include <stdlib.h>

#define MAX_FILE_NAME 14

struct file_descriptor *get_file_descriptor(int fd);
bool compare_file_descriptors(const struct list_elem *a, const struct list_elem *b, void *aux);

struct file_descriptor
{
  struct list_elem elem;
  int fd;
  struct file *file;
};

static bool create(const char *file_name, off_t initial_size);
static int read(int fd, const void *buffer, unsigned size);

static void syscall_handler (struct intr_frame *);
static struct lock files_lock; 


void syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&files_lock);
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

static bool has_bad_boundary(char *ptr)
{
  return validate_user_pointer(ptr) == NULL || validate_user_pointer(ptr + 3) == NULL;
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
      f->eax = write(f->esp);
      return;
    case SYS_EXIT:
      //printf("Calling SYS_EXIT\n");
      // TODO: handle exit code, files
      set_exit_code (thread_current (), *((int*)f->esp+1));
      thread_exit ();
    case SYS_FILESIZE:
      f->eax = filesize(*((uint32_t*)f->esp+1));
  		break;
    case SYS_CREATE:
      f->eax = create(*((uint32_t*)f->esp+1), *((uint32_t*)f->esp+2));
      break;
    case SYS_REMOVE:
      break;
    case SYS_OPEN:
      f->eax = open(*((uint32_t*)f->esp+1));
      break;
    case SYS_READ:
      f->eax = read(*((uint32_t*)f->esp+1), *((uint32_t*)f->esp+2), *((uint32_t*)f->esp+3));
      break;
    case SYS_CLOSE:
      close(*((uint32_t*)f->esp+1));
      break;
    case SYS_EXEC: {
      char *cmd_line = *((char **) f->esp + 1); // pointer to first argument
      f->eax = exec (cmd_line);
      break;
    }
    default:
      printf ("system call %d!\n", syscall_id);
      thread_exit ();
  }
}

static bool create(const char *file_name, off_t initial_size)
{
  if (validate_user_pointer(file_name) == NULL)
  {
    set_exit_code (thread_current (), -1);
    thread_exit ();
  }
  if (strlen(file_name) > MAX_FILE_NAME)
  {
    return false;
  }
  lock_acquire(&files_lock);
  bool success = filesys_create(file_name, initial_size);
  lock_release(&files_lock);
  return success;
}

int write(void *stack)
{
  int fd = *((int *) stack + 1);
  char *buffer = *((int *) stack + 2);
  int size = *((int *) stack + 3);
  if (fd == 1)
  {
    putbuf (buffer, size);
    return size;
  }
  

  if (validate_user_pointer(buffer) == NULL)
  {
    set_exit_code (thread_current (), -1);
    thread_exit ();
  }

  lock_acquire(&files_lock);
  struct file_descriptor *file_descriptor = get_file_descriptor(fd);
  if (file_descriptor == NULL)
  {
    lock_release(&files_lock);
    return 0;
  }
  
  off_t bytes_written = file_write (file_descriptor->file, buffer, size);

  lock_release(&files_lock);

  return bytes_written;
}

void handle_wait(void *stack)
{
  tid_t tid = *((int*)stack+1);
  return process_wait(tid);
}

int filesize(int fd) {

  lock_acquire(&files_lock);
  struct file_descriptor *file_descriptor = get_file_descriptor(fd);  

  if(file_descriptor == NULL) {
    lock_release(&files_lock);
    return -1;
  }

  lock_release(&files_lock);
  int size = file_length(file_descriptor->file);
  return file_length(file_descriptor->file); // Return the length of the file
}

int open(char *file_name)
{
  if (validate_user_pointer(file_name) == NULL)
  {
    set_exit_code (thread_current (), -1);
    thread_exit ();
  }
  if (strlen(file_name) > MAX_FILE_NAME)
  {
    return -1;
  }

  lock_acquire(&files_lock);
  struct file *file = filesys_open(file_name);
  struct list *fd_list = &thread_current()->file_descriptors;

  if (file == NULL)
  {
    lock_release(&files_lock);
    return -1;
  }

  struct thread *t = thread_current ();
  struct file_descriptor *current_fd_struct = malloc(sizeof(struct file_descriptor));
  current_fd_struct->file = file;

  int next_fd = 10;
  if (!list_empty(fd_list))
  {
    struct file_descriptor *cur_head = list_entry(list_front(fd_list), struct file_descriptor, elem);
    next_fd = cur_head->fd + 1;
  }
  
  current_fd_struct->fd = next_fd;
  list_push_front(fd_list, &current_fd_struct->elem);
  
  /*struct file_descriptor *head_fd_struct = list_entry(list_front(fd_list), struct file_descriptor, elem);
  head_fd_struct->fd = list_front(fd_list);
  current_fd_struct->fd = head_fd_struct->fd + 1;
  list_insert_ordered(fd_list, &current_fd_struct->elem, compare_file_descriptors, NULL);*/


  lock_release(&files_lock);
  return current_fd_struct->fd;
}

void close(int fd)
{
  lock_acquire(&files_lock);
  struct file_descriptor *file_descriptor = get_file_descriptor(fd);
  if (file_descriptor == NULL)
  {
    lock_release(&files_lock);
    return;
  }
  list_remove(&file_descriptor->elem);
  file_close(file_descriptor->file);
  free(file_descriptor);
  lock_release(&files_lock);
}

struct file_descriptor *get_file_descriptor(int fd)
{
  struct list_elem *e;
  struct thread *t = thread_current ();
  for (e = list_begin (&t->file_descriptors); e != list_end (&t->file_descriptors); e = list_next (e))
  {
    struct file_descriptor *f = list_entry (e, struct file_descriptor, elem);
    if (f->fd == fd)
    {
      return f;
    }
  }
  return NULL;
}

bool compare_file_descriptors(const struct list_elem *a, const struct list_elem *b, void *aux)
{
  struct file_descriptor *f1 = list_entry(a, struct file_descriptor, elem);
  struct file_descriptor *f2 = list_entry(b, struct file_descriptor, elem);
  return f1->fd > f2->fd;
}

static int read(int fd, const void *buffer, unsigned size)
{
  if (validate_user_pointer(buffer) == NULL)
  {
    set_exit_code (thread_current (), -1);
    thread_exit ();
  }

  lock_acquire(&files_lock);
  struct file_descriptor *file_descriptor = get_file_descriptor(fd);
  if (file_descriptor == NULL)
  {
    lock_release(&files_lock);
    return;
  }
  
  off_t bytes_read = file_read (file_descriptor->file, buffer, size);

  lock_release(&files_lock);

  return bytes_read;
}
