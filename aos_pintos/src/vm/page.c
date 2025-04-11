/*
create supplemental page table
get supplemental page
load a page into memory
delete page table entry from memory
*/

#include "vm/page.h"
#include "threads/vaddr.h"
#include <string.h>

struct supplemental_page_table_entry *
get_supplemental_page_table_entry (void *virtualAddress)
{
  struct thread *current_thread = thread_current ();
  struct list *supplemental_page_table =
      &current_thread->supplemental_page_table;

  struct list_elem *e;
  for (e = list_begin (supplemental_page_table);
       e != list_end (supplemental_page_table); e = list_next (e))
    {
      struct supplemental_page_table_entry *f =
          list_entry (e, struct supplemental_page_table_entry, elem);
      if (f->pageAdress == virtualAddress)
        {
          return f;
        }
    }
  return NULL;
}
struct supplemental_page_table_entry *
fte_to_spte (struct frame_entry* fte)
{
  struct thread *current_thread = thread_current ();
  struct list *supplemental_page_table =
      &current_thread->supplemental_page_table;

  struct list_elem *e;
  for (e = list_begin (supplemental_page_table);
       e != list_end (supplemental_page_table); e = list_next (e))
    {
      struct supplemental_page_table_entry *spte = list_entry (e, struct supplemental_page_table_entry, elem);

      uint32_t * physicalPage = pagedir_get_page(current_thread->pagedir, spte->pageAdress);
      //printf("SPTE page: %p | FTE page_entry: %p\n", physicalPage, fte->page_entry);

      if (physicalPage == fte->page_entry)
        {
          return spte;
        }
    }
  return NULL;
}

bool load_file (void *frame, struct supplemental_page_table_entry *spte)
{
  if (spte->type == PAGE_FILE || spte->type == PAGE_FILE_ZERO)
    {
      file_seek (spte->file, spte->offset); // reading page from file
      if (file_read (spte->file, frame, spte->read_bytes) !=
          (int) spte->read_bytes)
        {
          return false;
        }
      memset ((char *)frame + spte->read_bytes, 0, spte->zero_bytes);
    }
  else if (spte->type == PAGE_ZERO)
    {
      memset (frame, 0, PGSIZE);
    }
  else if (spte->is_swapped)
    {
      if (!swap_in (spte->swap_index, frame))
        {
          return false;
        }
      swap_free (spte->swap_index);
      spte->is_swapped = false;
    }
  // installing page into process's pt
  if (!install_page (spte->pageAdress, frame, spte->writable))
    {
      return false;
    }
  spte->isFaulted = false;
  return true;
}

void clear_supplemental_page_entries (struct list *page_table_entries)
{
  struct list_elem *e;
  for (e = list_begin (&page_table_entries);
       e != list_end (&page_table_entries); e = list_next (e))
    {
      struct supplemental_page_table_entry *f =
          list_entry (e, struct supplemental_page_table_entry, elem);
      free_frame (f->pageAdress);
      free (f);
    }
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

  // Allocate a frame for the new stack page
  struct frame_entry* frame_entry = allocate_frame(PAL_USER | PAL_ZERO);
  if (frame_entry == NULL)
    return false;

  // Create supplemental page table entry
  struct supplemental_page_table_entry *pte = malloc(sizeof(struct supplemental_page_table_entry));
  if (pte == NULL) {
    // Need to free the frame that was allocated
    free_frame(frame_entry);
    return false;
  }


  // Setup the supplemental page table entry
  pte->pageAdress = virtual_page;             // The virtual address for this page
  pte->read_bytes = 0;
  pte->zero_bytes = 0;
  pte->file = NULL;
  pte->offset = 0;
  pte->writable = true;
  pte->owner = thread_current();
  pte->isFaulted = false;
  pte->type = PAGE_STACK;

  // Map the physical frame to the virtual page
  if (!install_page(virtual_page, frame_entry->page_entry, true)) {
    free(pte);
    free_frame(frame_entry);
    return false;
  }

  // Add the page to the process's supplemental page table
  struct thread *current = thread_current();
  lock_acquire(&current->supplemental_page_table_lock);
  list_push_back(&current->supplemental_page_table, &pte->elem);
  lock_release(&current->supplemental_page_table_lock);

  return true;
}
