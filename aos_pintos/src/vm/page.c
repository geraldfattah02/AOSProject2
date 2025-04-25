/*
create supplemental page table
get supplemental page
load a page into memory
delete page table entry from memory
*/

#include "vm/page.h"
#include "threads/vaddr.h"
#include <string.h>
#include "filesys/file.h"

struct sup_page_table_entry *
lookup_sup_page_entry (void *upage)
{
  struct thread *current_thread = thread_current ();
  lock_acquire (&current_thread->supplemental_page_table_lock);
  struct list *supplemental_page_table =
      &current_thread->supplemental_page_table;

  struct list_elem *e;
  for (e = list_begin (supplemental_page_table);
       e != list_end (supplemental_page_table);
       e = list_next (e))
  {
    struct sup_page_table_entry *f =
      list_entry (e, struct sup_page_table_entry, elem);
    if (f->user_page == upage)
    {
      lock_release (&current_thread->supplemental_page_table_lock);
      return f;
    }
  }
  lock_release (&current_thread->supplemental_page_table_lock);
  return NULL;
}

/* Fill the given frame with page data */
bool load_spte_into_frame (void *frame, struct sup_page_table_entry *spte)
{
  bool success;
  if (spte->is_swapped)
  {
    success = swap_in (spte->swap_index, frame);
    if (!success)
      return false;
    spte->is_swapped = false;
  }
  else if (spte->page_type == PAGE_FROM_FILE)
  {
    file_seek (spte->file, spte->offset); // reading page from file
    if (file_read (spte->file, frame, spte->read_bytes) != (int32_t) spte->read_bytes)
      return false;
    
    memset ((char*) frame + spte->read_bytes, 0, spte->zero_bytes);
  }
  else if (spte->page_type == PAGE_ALL_ZERO)
  {
    memset (frame, 0, PGSIZE);
  }
  else {
    PANIC("Unable to load spte into frame.\n");
  }

  // Add mapping from user page to frame
  DPRINT ("Installing %p, %p, %d\n", spte->user_page, frame, spte->writable);
  if (!install_page (spte->user_page, frame, spte->writable))
  {
    return false;
  }

  return true;
}

/* Setup supplemental entry for a file page */
struct sup_page_table_entry *
init_file_entry (void *upage, struct file *file, off_t offset, bool writable,
                 uint32_t read_bytes, uint32_t zero_bytes)
{
  struct sup_page_table_entry *entry = malloc (sizeof (struct sup_page_table_entry));
  if (entry == NULL)
    return NULL;

  entry->user_page = upage;
  entry->read_bytes = read_bytes;
  entry->zero_bytes = zero_bytes;
  entry->file = file;
  entry->offset = offset;
  entry->writable = writable;
  entry->is_swapped = false;

  if (read_bytes > 0)
  {
    entry->page_type = PAGE_FROM_FILE;
  }
  else
  {
    entry->page_type = PAGE_ALL_ZERO;
  }

  return entry;
}

/* Setup supplemental entry for the stack */
static struct sup_page_table_entry *
init_stack_entry (void *upage)
{
  // Create supplemental page table entry
  struct sup_page_table_entry *pte = malloc (sizeof (struct sup_page_table_entry));
  if (pte == NULL)
    return NULL;

  // Setup the supplemental page table entry
  pte->user_page = upage;
  pte->read_bytes = 0;
  pte->zero_bytes = 0;
  pte->file = NULL;
  pte->offset = 0;
  pte->writable = true;
  pte->page_type = PAGE_ALL_ZERO;
  pte->is_swapped = false;

  return pte;
}

void add_stack_entry (void *upage)
{
  struct sup_page_table_entry *spte = init_stack_entry (upage);

  struct thread *current = thread_current ();
  lock_acquire (&current->supplemental_page_table_lock);
  list_push_back (&current->supplemental_page_table, &spte->elem);
  lock_release (&current->supplemental_page_table_lock);
}

/* Grow the stack at given virtual page. */
bool grow_stack (void *virtual_page) 
{
  ASSERT (is_user_vaddr (virtual_page));

  // Round down to page boundary
  virtual_page = pg_round_down (virtual_page);
  
  // Check if we're exceeding the max stack size
  if (((uint32_t) PHYS_BASE - (uint32_t) virtual_page) >= MAX_STACK_SIZE) {
    return false;
  }

  // Allocate a frame for the new stack page
  struct frame_table_entry* frame_entry = allocate_frame (PAL_USER | PAL_ZERO);
  if (frame_entry == NULL)
    return false;

  struct sup_page_table_entry *spte = init_stack_entry (virtual_page);
  if (spte == NULL)
  {
    free_frame_entry (frame_entry);
    return NULL;
  }

  frame_entry->current_sup_page = spte;
  frame_entry->pinned = false;

  // Map the physical frame to the virtual page
  if (!install_page (virtual_page, frame_entry->kpage_addr, true))
  {
    free (spte);
    free_frame_entry (frame_entry);
    return false;
  }

  // Add the page to the process's supplemental page table
  struct thread *current = thread_current ();
  lock_acquire (&current->supplemental_page_table_lock);
  list_push_back (&current->supplemental_page_table, &spte->elem);
  lock_release (&current->supplemental_page_table_lock);

  return true;
}

/* Free supplemental page table resources. */
void clear_current_supplemental_page_table ()
{
  lock_acquire (&thread_current ()->supplemental_page_table_lock);
  struct list *sup_page_table = &thread_current ()->supplemental_page_table;
  struct sup_page_table_entry *entry;
  uint32_t *pagedir = thread_current ()->pagedir;

  while (!list_empty (sup_page_table))
  {
    struct list_elem *cur = list_pop_back (sup_page_table);
    entry = list_entry (cur, struct sup_page_table_entry, elem);

    // Remove page from pagedir
    void *kpage = pagedir_get_page (pagedir, entry->user_page);
    pagedir_clear_page (pagedir, entry->user_page);

    // Free supplemental and frame table entries
    if (kpage != NULL)
    {
      free_frame_entry ( find_frame_entry (kpage));
    }
    free (entry);
  }
  lock_release (&thread_current ()->supplemental_page_table_lock);
}
