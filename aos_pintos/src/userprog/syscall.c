#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/block.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <string.h>
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include <stdlib.h>

struct file_descriptor *get_file_descriptor(int fd);
bool compare_file_descriptors(const struct list_elem *a, const struct list_elem *b, void *aux);

struct file_descriptor
{
  struct list_elem elem;
  int fd;
  struct file *file;
};


static void syscall_handler (struct intr_frame *);
static struct lock files_lock; 


void syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&files_lock);
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

static void syscall_handler (struct intr_frame *f)
{
  // Check if esp is valid, and the arguments (at most 3) are not in kernel space
  if (validate_user_pointer(f->esp) == NULL || is_kernel_vaddr((int*)f->esp + 3) || (uint32_t)f->esp % 4 != 0)
  {
    set_exit_code (thread_current (), -1);
    thread_exit ();
  }
  // printf ("system call %p\n", f->esp);
  int syscall_id = *((int*) f->esp);
  // printf ("system call %d!\n", syscall_id);

  switch (syscall_id) {
    case SYS_WRITE:
      write(f->esp);
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
      break;
    case SYS_CLOSE:
      close(*((uint32_t*)f->esp+1));
      break;
    default:
      printf ("system call %d!\n", syscall_id);
      thread_exit ();
  }
}

bool create(const char *file_name, unsigned initial_size)
{
  lock_acquire(&files_lock);
  bool success = filesys_create(file_name, initial_size);
  lock_release(&files_lock);
  return success;
}

void write(void *stack)
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
  struct file_descriptor *head_fd_struct = list_entry(list_front(fd_list), struct file_descriptor, elem);

  head_fd_struct->fd = list_front(&fd_list);
  current_fd_struct->fd = head_fd_struct->fd + 1;
  list_insert_ordered(fd_list, &current_fd_struct->elem, compare_file_descriptors, NULL);


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
  