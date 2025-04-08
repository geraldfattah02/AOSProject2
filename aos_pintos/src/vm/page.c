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
