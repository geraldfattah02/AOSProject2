#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/block.h"
#include "threads/interrupt.h"
#include <string.h>
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "process.h"
#include <stdlib.h>

#define MAX_FILE_NAME 14

/* Lock required for file system access */
static struct lock filesys_lock;

/* Record for a file currently open by a thread */
struct file_descriptor
{
  struct list_elem elem;     /* List element */
  int fd;                    /* ID for this file descriptor */
  struct file *file;         /* Pointer to open file handle */
};

/* Get a file descriptor by ID */
struct file_descriptor *get_file_descriptor (int fd)
{
  struct list_elem *e;
  struct thread *t = thread_current ();
  struct list *open_files = &t->file_descriptors;
  for (e = list_begin (open_files); e != list_end (open_files); e = list_next (e))
  {
    struct file_descriptor *f = list_entry (e, struct file_descriptor, elem);
    if (f->fd == fd)
    {
      return f;
    }
  }
  return NULL;
}

/* System call handlers */
static void halt ();
static void exit (int status);
static tid_t exec (const char *cmd_line);
static int wait (tid_t tid);
static bool create (const char *file, unsigned initial_size);
static bool remove (const char *file);
static int open (const char *file);
static int filesize (int fd);
static int read (int fd, void *buffer, unsigned size);
static int write (int fd, const void *buffer, unsigned size);
static void seek (int fd, unsigned position);
static unsigned tell (int fd);
static void close (int fd);
static int symlink (char *target, char *linkpath);

/* Initialize syscall */
static void syscall_handler (struct intr_frame *);

void syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&filesys_lock);
}

/* Check if user pointer is valid */
static void *validate_user_pointer (void *user_ptr)
{
  if (user_ptr == NULL)           // Pointer is NULL
    return NULL; 
  if (is_kernel_vaddr (user_ptr)) // Pointer to kernel virtual address space
    return NULL; 

  struct thread *t = thread_current ();
  return pagedir_get_page (t->pagedir, user_ptr); // Return kernel virtual address, or NULL if unmapped
}

/* Check if system call goes across a bad memory boundary */
static bool has_bad_boundary(char *ptr)
{
  // +15 needed for boundary checking the entire system call (id + 3 args = 16 bytes)
  return validate_user_pointer (ptr) == NULL 
         || validate_user_pointer (ptr + 15) == NULL;
}

/* Set a thread's status code */
static void set_exit_code (struct thread *t, int code)
{
  if (t->parent_record != NULL)
    t->parent_record->exit_code = code;
}

/* Macro for getting arguments off the stack */
#define arg(STACK, NUM)     \
  (*((uint32_t*)STACK + NUM))

/* Dispath system call based on the ID from the interrupt */
static void syscall_handler (struct intr_frame *f)
{
  // Check if esp is valid and aligned, and that the arguments (at most 3) are not in kernel space
  if (validate_user_pointer(f->esp) == NULL || has_bad_boundary(f->esp))
  {
    set_exit_code (thread_current (), -1);
    thread_exit ();
  }

  int syscall_id = arg (f->esp, 0);

  switch (syscall_id) {
    case SYS_HALT:
      halt ();
      return;
    case SYS_EXIT:
      exit (arg (f->esp, 1));
      return;
    case SYS_EXEC:
      f->eax = exec (arg (f->esp, 1));
      return;
    case SYS_WAIT:
      f->eax = wait (arg (f->esp, 1));
      return;
    case SYS_CREATE:
      f->eax = create(arg (f->esp, 1), arg (f->esp, 2));
      return;
    case SYS_REMOVE:
      f->eax = remove(arg (f->esp, 1));
      return;
    case SYS_OPEN:
      f->eax = open(arg (f->esp, 1));
      return;
    case SYS_FILESIZE:
      f->eax = filesize(arg (f->esp, 1));
  		return;
    case SYS_READ:
      f->eax = read(arg (f->esp, 1), arg (f->esp, 2), arg (f->esp, 3));
      return;
    case SYS_WRITE:
      f->eax = write(arg (f->esp, 1), arg (f->esp, 2), arg (f->esp, 3));
      return;
    case SYS_SEEK:
      seek(arg (f->esp, 1), arg (f->esp, 2));
      return;
    case SYS_TELL:
      f->eax = tell(arg (f->esp, 1));
      return;
    case SYS_CLOSE:
      close(arg (f->esp, 1));
      return;
    case SYS_SYMLINK:
      f->eax = symlink(arg (f->esp, 1), arg (f->esp, 2));
      return;
    default:
      printf ("system call %d not implemented\n", syscall_id);
      thread_exit ();
  }
}

/* HALT the system */
static void halt ()
{
  shutdown_power_off ();
}

/* EXIT the current thread */
static void exit (int status)
{
  set_exit_code (thread_current (), status);
  thread_exit ();
}

/* WAIT for the thread with given id */
static int wait (tid_t tid)
{
  return process_wait (tid);
}

/* EXEC the given command */
static tid_t exec (const char *cmd_line)
{
  char *kernel_space_cmd = validate_user_pointer (cmd_line);
  if (kernel_space_cmd == NULL)
  {
    set_exit_code (thread_current (), -1);
    thread_exit ();
  }

  uint32_t len = strlen (kernel_space_cmd);
  if (validate_user_pointer (cmd_line + len) == NULL)
  {
    set_exit_code (thread_current (), -1);
    thread_exit ();
  }

  lock_acquire (&filesys_lock);
  tid_t child_pid = process_execute (kernel_space_cmd);
  lock_release (&filesys_lock);

  return child_pid;
}

/* CREATE a file */
static bool create (const char *file, unsigned initial_size)
{
  if (validate_user_pointer (file) == NULL)
  {
    set_exit_code (thread_current (), -1);
    thread_exit ();
  }

  if (strlen (file) > MAX_FILE_NAME)
  {
    return false;
  }

  lock_acquire (&filesys_lock);
  bool success = filesys_create (file, initial_size);
  lock_release (&filesys_lock);

  return success;
}

/* REMOVE a file */
static bool remove (const char *file)
{
  if (validate_user_pointer (file) == NULL)
  {
    set_exit_code (thread_current (), -1);
    thread_exit ();
  }

  if (strlen (file) > MAX_FILE_NAME)
  {
    return false;
  }

  lock_acquire (&filesys_lock);
  bool success = filesys_remove (file);
  lock_release (&filesys_lock);

  return success;
}

/* OPEN a file */
static int open (const char *file_name)
{
  if (validate_user_pointer (file_name) == NULL)
  {
    set_exit_code (thread_current (), -1);
    thread_exit ();
  }

  if (strlen (file_name) > MAX_FILE_NAME)
  {
    return -1;
  }

  lock_acquire (&filesys_lock);
  struct file *file = filesys_open (file_name);
  lock_release (&filesys_lock);

  if (file == NULL)
  {
    return -1;
  }

  struct thread *t = thread_current ();
  struct file_descriptor *current_fd_struct = malloc (sizeof (struct file_descriptor));
  if (current_fd_struct == NULL)
  {
    return -1;
  }

  current_fd_struct->file = file;

  int next_fd = 10;
  struct list *fd_list = &t->file_descriptors;
  if (!list_empty (fd_list))
  {
    struct file_descriptor *cur_head = list_entry (list_front (fd_list), struct file_descriptor, elem);
    next_fd = cur_head->fd + 1;
  }
  
  current_fd_struct->fd = next_fd;
  list_push_front (fd_list, &current_fd_struct->elem);

  return current_fd_struct->fd;
}

/* Get the file size */
static int filesize (int fd)
{
  struct file_descriptor *file_descriptor = get_file_descriptor (fd);  
  if(file_descriptor == NULL) {
    return -1;
  }
  
  lock_acquire (&filesys_lock);
  int size = file_length (file_descriptor->file);
  lock_release (&filesys_lock);

  return size;
}

/* READ a file */
static int read (int fd, void *buffer, unsigned size)
{
  char *end = (char*)buffer + size - 1;
  if (validate_user_pointer (buffer) == NULL || validate_user_pointer (end) == NULL)
  {
    set_exit_code (thread_current (), -1);
    thread_exit ();
  }

  if (fd == STDIN_FILENO)
  {
    unsigned len = 0;
    uint8_t c;
    // Read size bytes, or until EOF (-1)
    while (len < size && (c = input_getc()) >= 0)
    {
      *(uint8_t*) buffer = c;
      len += 1;
      *(uint8_t*) buffer += 1;
    }
    
    return len;
  }

  struct file_descriptor *file_descriptor = get_file_descriptor (fd);
  if (file_descriptor == NULL)
  {
    return -1;
  }
  
  lock_acquire (&filesys_lock);
  off_t bytes_read = file_read (file_descriptor->file, buffer, size);
  lock_release (&filesys_lock);

  return bytes_read;
}

/* WRITE to a file */
static int write (int fd, const void *buffer, unsigned size)
{
  char *end = (char*)buffer + size - 1;
  if (validate_user_pointer (buffer) == NULL || validate_user_pointer (end) == NULL)
  {
    set_exit_code (thread_current (), -1);
    thread_exit ();
  }

  if (fd == STDOUT_FILENO)
  {
    putbuf (buffer, size);
    return size;
  }

  struct file_descriptor *file_descriptor = get_file_descriptor (fd);
  if (file_descriptor == NULL)
  {
    return 0;
  }
  
  lock_acquire (&filesys_lock);
  off_t bytes_written = file_write (file_descriptor->file, buffer, size);
  lock_release (&filesys_lock);

  return bytes_written;
}

/* SEEK to a location in a file */
static void seek (int fd, unsigned position)
{
  struct file_descriptor *file_descriptor = get_file_descriptor (fd);
  if (file_descriptor == NULL)
  {
    return;
  }

  lock_acquire (&filesys_lock);
  file_seek (file_descriptor->file, position);
  lock_release (&filesys_lock);
}

/* Return the next byte position to read/write */
static unsigned tell (int fd)
{
  struct file_descriptor *file_descriptor = get_file_descriptor (fd);
  if (file_descriptor == NULL)
  {
    return 0;
  }

  lock_acquire (&filesys_lock);
  off_t result = file_tell (file_descriptor->file);
  lock_release (&filesys_lock);

  return result;
}

/* CLOSE a file */
static void close (int fd)
{
  struct file_descriptor *file_descriptor = get_file_descriptor (fd);
  if (file_descriptor == NULL)
  {
    return;
  }

  lock_acquire (&filesys_lock);
  file_close (file_descriptor->file);
  lock_release (&filesys_lock);

  list_remove (&file_descriptor->elem);
  free (file_descriptor);
}

/* Create a symlink */
static int symlink (char *target, char *linkpath)
{
  if (validate_user_pointer (target) == NULL || validate_user_pointer (linkpath) == NULL)
  {
    set_exit_code (thread_current (), -1);
    thread_exit ();
  }

  if (strlen (target) > MAX_FILE_NAME || strlen (linkpath) > MAX_FILE_NAME)
  {
    return -1;
  }

  lock_acquire (&filesys_lock);
  struct file *target_file = filesys_open (target);
  if (target_file == NULL){
    lock_release (&filesys_lock);
    return -1;
  }

  bool success = filesys_symlink (target, linkpath);
  lock_release (&filesys_lock);

  return success ? 0 : -1;
}

/* Free the resources owned by a thread */
void free_thread_resources (struct thread *t)
{
  lock_acquire (&filesys_lock);
  file_close (t->executable);

  while (!list_empty (&t->file_descriptors))
    {
      struct list_elem *e = list_pop_front (&t->file_descriptors);
      struct file_descriptor *f = list_entry (e, struct file_descriptor, elem);
      file_close (f->file);
      free (f);
    }

  lock_release (&filesys_lock);
}
