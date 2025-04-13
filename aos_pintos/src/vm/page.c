/*
create supplemental page table
get supplemental page
load a page into memory
delete page table entry from memory
*/

#include "vm/page.h"
#include "threads/vaddr.h"
#include <string.h>

struct sup_page_table_entry *
lookup_sup_page_entry (void *upage)
{
  struct thread *current_thread = thread_current ();
  struct list *supplemental_page_table =
      &current_thread->supplemental_page_table;

  struct list_elem *e;
  for (e = list_begin (supplemental_page_table);
       e != list_end (supplemental_page_table); e = list_next (e))
    {
      struct sup_page_table_entry *f =
          list_entry (e, struct sup_page_table_entry, elem);
      if (f->user_page == upage)
        {
          return f;
        }
    }
  return NULL;
}

bool load_file (void *frame, struct sup_page_table_entry *spte)
{
  if (spte->is_swapped)
    {
      DPRINT ("Loading Swap\n");
      if (!swap_in (spte->swap_index, frame))
        {
          return false;
        }
      swap_free (spte->swap_index);
      spte->is_swapped = false;
    }
  else if (spte->page_type == PAGE_FROM_FILE)
    {
      DPRINT ("Loading file\n");
      file_seek (spte->file, spte->offset); // reading page from file
      if (file_read (spte->file, frame, spte->read_bytes) !=
          (int) spte->read_bytes)
        {
          return false;
        }
      memset ((char *)frame + spte->read_bytes, 0, spte->zero_bytes);
    }
  else if (spte->page_type == PAGE_ALL_ZERO)
    {
      DPRINT ("Loading Zero\n");
      memset (frame, 0, PGSIZE);
    }
  else {
    PANIC("unable to load file\n");
  }
  DPRINT ("Installing %p, %p, %d\n", spte->user_page, frame, spte->writable);
  // installing page into process's pt
  if (!install_page (spte->user_page, frame, spte->writable))
    {
      return false;
    }
  DPRINT ("Installed\n");
  return true;
}

struct sup_page_table_entry *init_stack_entry (void *upage, struct frame_table_entry *frame)
{
  DPRINT ("frame_entry %p, virt: %p\n", frame_entry->kpage_addr, virtual_page);

  // Create supplemental page table entry
  struct sup_page_table_entry *pte = malloc(sizeof(struct sup_page_table_entry));
  if (pte == NULL) {
    // Need to free the frame that was allocated
    free_frame(frame->kpage_addr);
    return false;
  }

  frame->current_sup_page = pte;

  // Setup the supplemental page table entry
  pte->user_page = upage;             // The virtual address for this page
  pte->read_bytes = 0;
  pte->zero_bytes = 0;
  pte->file = NULL;
  pte->offset = 0;
  pte->writable = true;
  pte->page_type = PAGE_ALL_ZERO;
  pte->is_swapped = false;

  return pte;
}

bool grow_stack(void *virtual_page) 
{
  ASSERT (is_user_vaddr (virtual_page));

  // Round down to page boundary
  virtual_page = pg_round_down(virtual_page);
  
  // Check if we're exceeding the max stack size
  if ((size_t)((uintptr_t)PHYS_BASE - (uintptr_t)virtual_page) > MAX_STACK_SIZE) {
    return false;
  }

  DPRINT ("Allocating Stack\n");

  // Allocate a frame for the new stack page
  struct frame_table_entry* frame_entry = allocate_frame(PAL_USER | PAL_ZERO);
  if (frame_entry == NULL)
    return false;

  struct sup_page_table_entry *spte = init_stack_entry (virtual_page, frame_entry);

  DPRINT ("Mapping\n");

  // Map the physical frame to the virtual page
  if (!install_page(virtual_page, frame_entry->kpage_addr, true)) {
    DPRINT ("Failed map\n");
    free(spte);
    free_frame(frame_entry);
    return false;
  }

  // Add the page to the process's supplemental page table
  struct thread *current = thread_current();
  lock_acquire(&current->supplemental_page_table_lock);
  list_push_back(&current->supplemental_page_table, &spte->elem);
  lock_release(&current->supplemental_page_table_lock);

  DPRINT ("Added spte\n");

  return true;
}

void clear_current_supplemental_page_table ()
{
  struct list *sup_page_table = &thread_current ()->supplemental_page_table;
  struct sup_page_table_entry *entry;

  while (!list_empty (sup_page_table))
    {
      struct list_elem *cur = list_pop_back (sup_page_table);
      entry = list_entry (cur, struct sup_page_table_entry, elem);

      void *kpage = pagedir_get_page(thread_current ()->pagedir, entry->user_page);
      DPRINT ("Clear/Free %p, frame? %p\n", entry->user_page, kpage);
      pagedir_clear_page (thread_current ()->pagedir, entry->user_page);
      if (kpage != NULL)
        {
          free_frame (kpage);
        }
      free (entry);
    }
}
