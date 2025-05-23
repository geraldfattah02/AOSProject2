#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "vm/page.h"

#define MAX_ARG_LEN ((PGSIZE / 4) * 3) /* Allow up to 3Kb */
#define MAX_ARGC (((PGSIZE / 4) - sizeof(uint32_t)) / sizeof (char*))
struct process_arguments {
  char arg_strings[MAX_ARG_LEN]; 
  char *argv[MAX_ARGC];
  uint32_t argc;
};

/* Break argument string into argv and argc */
static bool parse_process_arguments (struct process_arguments *args)
{
  char *token, *save_ptr;
  uint32_t i = 0;
  for (token = strtok_r (args->arg_strings, " ", &save_ptr);
       token != NULL;
       token = strtok_r (NULL, " ", &save_ptr))
  {
    if (i >= MAX_ARGC)
    {
      return false;
    }
    args->argv[i++] = token;
  }
  args->argc = i;
  return true;
}


static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp,
                  struct process_arguments *unparsed_args);
/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t process_execute (const char *file_and_args)
{
  struct process_arguments *args;
  tid_t tid;

  /* Make a copy of file name and args.
     Otherwise there's a race between the caller and load(). */
  args = palloc_get_page (0);
  if (args == NULL)
    return TID_ERROR;

  strlcpy ((char*) args, file_and_args, MAX_ARG_LEN);
  if (!parse_process_arguments (args))
  {
    palloc_free_page (args);
    return TID_ERROR;
  }

  char *name = args->argv[0];
  struct child_thread *record = malloc (sizeof (struct child_thread));
  list_push_back (&thread_current ()->child_records, &record->elem);
  sema_init (&record->wait_child, 0);
  lock_init (&record->free_lock);
  
  /* Create a new thread to execute FILE_NAME. */
  
  record->should_free = false;
  record->loaded_successfully = false;

  struct file *executable = filesys_open (name);
  if (executable == NULL)
  {
    palloc_free_page (args);
    return TID_ERROR;
  }
  file_close (executable);

  tid = thread_create (name, PRI_DEFAULT, start_process, args, record);
  if (tid == TID_ERROR)
  {
    palloc_free_page (args);
    return TID_ERROR;
  }

  // Wait until the child process loads
  sema_down (&record->wait_child);
  if (!record->loaded_successfully)
  {
    return TID_ERROR;
  }

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process (void *aux)
{
  struct process_arguments *args = aux;
  char *file_name = args->argv[0];
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  
  success = load (file_name, &if_.eip, &if_.esp, args);

  if (success)
  {
    struct file *executable = filesys_open (file_name);
    thread_current ()->executable = executable;
    file_deny_write (executable);
  }

  /* Must come after file accesses above.
    - sema_up will wake up the parent, which might also try
    to access the file system and cause a race condition */

  struct thread *t = thread_current ();
  if (t->parent_record)
  {
    if (!success)
    {
      t->parent_record->exit_code = -1;
    }
    t->parent_record->loaded_successfully = success;
    sema_up (&t->parent_record->wait_child);
  }

  /* If load failed, quit. */
  palloc_free_page (aux);
  if (!success)
    thread_exit ();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait (tid_t child_tid)
{
  struct list_elem *e;
  struct child_thread *child = NULL;
  struct list *list = &thread_current ()->child_records;
  for (e = list_begin (list); e != list_end (list); e = list_next (e))
  {
    child = list_entry (e, struct child_thread, elem);
    if (child->tid == child_tid)
      break;
  }

  if (e == list_tail (list)) // No child with this tid
    return -1;

  sema_down (&child->wait_child);
  int exit_code = child->exit_code;

  list_remove (&child->elem);
  free (child);

  return exit_code;
}

/* Free the current process's resources. */
void process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
{
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
{
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack (void **esp, struct process_arguments *args);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load (const char *file_name, void (**eip) (void), void **esp,
           struct process_arguments *args)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done;
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 ||
      ehdr.e_machine != 3 || ehdr.e_version != 1 ||
      ehdr.e_phentsize != sizeof (struct Elf32_Phdr) || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
          case PT_NULL:
          case PT_NOTE:
          case PT_PHDR:
          case PT_STACK:
          default:
            /* Ignore this segment. */
            break;
          case PT_DYNAMIC:
          case PT_INTERP:
          case PT_SHLIB:
            goto done;
          case PT_LOAD:
            if (validate_segment (&phdr, file))
              {
                bool writable = (phdr.p_flags & PF_W) != 0;
                uint32_t file_page = phdr.p_offset & ~PGMASK;
                uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
                uint32_t page_offset = phdr.p_vaddr & PGMASK;
                uint32_t read_bytes, zero_bytes;
                if (phdr.p_filesz > 0)
                  {
                    /* Normal segment.
                       Read initial part from disk and zero the rest. */
                    read_bytes = page_offset + phdr.p_filesz;
                    zero_bytes =
                        (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE) -
                         read_bytes);
                  }
                else
                  {
                    /* Entirely zero.
                       Don't read anything from disk. */
                    read_bytes = 0;
                    zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                  }
                if (!load_segment (file, file_page, (void *) mem_page,
                                   read_bytes, zero_bytes, writable))
                  goto done;
              }
            else
              goto done;
            break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, args))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  return success;
}

/* load() helpers. */

bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Setup a virtual memory page. */
      struct sup_page_table_entry *entry =
        init_file_entry (upage, file, ofs, writable, page_read_bytes, page_zero_bytes);

      struct thread *current = thread_current ();
      lock_acquire (&current->supplemental_page_table_lock);
      list_push_back (&current->supplemental_page_table, &entry->elem);
      lock_release (&current->supplemental_page_table_lock);
        
      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
      ofs += PGSIZE;
    }
  file_seek (file, ofs);
  return true;
}

/* Storing data for dynamic number of arguments */
struct argument {
  struct list_elem elem;  /* List elem */
  void *addr;             /* Address of argument on the stack */
};

/* Push a string value onto the stack and add to argument list */
static char * push_string (char **esp, const char *value)
{
  uint32_t len = strlen (value) + 1;
  *esp -= len;
  memcpy (*esp, value, len);
  return *esp;
}

/* Push a 4 byte value onto the stack */
static void push_4byte(char **stack, uint32_t value)
{
  uint32_t **esp = (uint32_t**) stack;
  *esp -= 1;
  **esp = value;
}

/* Push arguments on the stack and setup argc, argv */
static bool pass_arguments (char **esp, struct process_arguments *args)
{
  for (uint32_t i = 0; i < args->argc; i++)
  {
    args->argv[i] = push_string (esp, args->argv[i]);
  }

  // 4-byte word alignment 
  *esp -= ((uint32_t) *esp) % 4;

  // Add NULL sentinel
  push_4byte (esp, 0);

  // Push arg addresses (in reverse)
  for (int i = (int) args->argc - 1; i >= 0; i--)
  {
    push_4byte (esp, (uint32_t) args->argv[i]);
  }

  // Add argv
  push_4byte (esp, (uint32_t) *esp);

  // Add argc
  push_4byte (esp, args->argc);

  // Add empty return address
  push_4byte (esp, 0);

  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack (void **esp, struct process_arguments *args)
{
  // Calculate the address for the stack page (one page below PHYS_BASE)
  void *stack_page = ((uint8_t *)PHYS_BASE) - PGSIZE;
  
  // Call the grow_stack_one_page function to allocate and map the page
  if (!grow_stack (stack_page))
    return false;

  // Set initial stack pointer to the top of user memory
  *esp = PHYS_BASE;
  
  // Now load arguments onto the stack
  pass_arguments ((char**) esp, args);
  
  return true;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL &&
          pagedir_set_page (t->pagedir, upage, kpage, writable));
}
