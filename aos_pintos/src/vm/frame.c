#include "../threads/palloc.h"
#include "../threads/malloc.h"
#include "../lib/kernel/list.h"
#include "../lib/debug.h"
#include "frame.h"
#include "../threads/synch.h"
#include "../userprog/pagedir.h"
#include "../threads/thread.h"
#include "swap.h"
#include "page.h"

struct list frame_table;
struct lock frame_table_lock;

static void evict_page (void);

/* Initialize the frame table. */
void init_frame_table (void)
{
  list_init (&frame_table);
  lock_init (&frame_table_lock);
}

/* Allocate a new frame. */
struct frame_table_entry *
allocate_frame (enum palloc_flags flags) 
{
  lock_acquire (&frame_table_lock);
  void *page = palloc_get_page (flags);

  if (page == NULL)
  {
    evict_page ();
    page = palloc_get_page (flags);
  }

  ASSERT (page != NULL);
  
  struct frame_table_entry *frame = malloc (sizeof (struct frame_table_entry));
  if (frame == NULL)
  {
    lock_release (&frame_table_lock);
    set_exit_code (thread_current (), -1);
    thread_exit ();
  }

  frame->kpage_addr = page;
  frame->owner_thread = thread_current ();
  frame->pinned = true;

  DPRINT ("Allocating frame %p for %p\n", page, thread_current ());

  list_push_back (&frame_table, &frame->elem);
  lock_release (&frame_table_lock);
  
  return frame;
}

/* Free a frame entry. */
void free_frame_entry (struct frame_table_entry *entry)
{
  bool locked = lock_held_by_current_thread (&frame_table_lock);
  if (!locked)
    lock_acquire (&frame_table_lock);

  list_remove (&entry->elem);

  if (!locked)
    lock_release (&frame_table_lock);

  palloc_free_page (entry->kpage_addr);
  free (entry);
}

/* Used to cycle through the frame table. */
struct list_elem *eviction_pointer = NULL;

/* Implements an LRU eviction policy. Cycle through the page table, checking access bits.
   If true, set to false. Else, this frame entry becomes the victim. */
static struct frame_table_entry *
eviction_policy (void)
{
  struct frame_table_entry *victim = NULL;
  
  if (eviction_pointer == NULL || eviction_pointer == list_end (&frame_table))
  {
    eviction_pointer = list_begin (&frame_table);
    struct frame_table_entry *f = list_entry (eviction_pointer, struct frame_table_entry, elem);
    victim = f;
  }

  // Iterate using the eviction pointer
  while (true)
  {
    if (eviction_pointer == list_end (&frame_table))
    {
      eviction_pointer = list_begin (&frame_table);
    }

    struct frame_table_entry *f = list_entry (eviction_pointer, struct frame_table_entry, elem);
    eviction_pointer = list_next (eviction_pointer);  // advance for next iteration

    if (f->pinned)
      continue;

    struct sup_page_table_entry *spte = f->current_sup_page;
    if (spte == NULL)
      continue;

    lock_acquire (&f->owner_thread->supplemental_page_table_lock);
    if (!pagedir_is_accessed (f->owner_thread->pagedir, spte->user_page))
    {
      victim = f;
      lock_release (&f->owner_thread->supplemental_page_table_lock);
      break;
    }
    
    pagedir_set_accessed (f->owner_thread->pagedir, spte->user_page, false);
    lock_release (&f->owner_thread->supplemental_page_table_lock);
  }

  return victim;
} 

/* Find a page according to the eviction_policy, and evict it.
   Assumes frame table lock is held by current thread. */
static void evict_page ()
{
  ASSERT (lock_held_by_current_thread (&frame_table_lock));
  struct frame_table_entry *victim = eviction_policy ();
  struct sup_page_table_entry *spte = victim->current_sup_page;
  lock_acquire (&victim->owner_thread->supplemental_page_table_lock);

  // Check if the page is dirty and swap it out if necessary
  if (pagedir_is_dirty (victim->owner_thread->pagedir, spte->user_page)
      || spte->page_type == PAGE_CHANGED)
  {
    // Swap out the page
    spte->page_type = PAGE_CHANGED;
    lock_release (&frame_table_lock);
    swap_index_t swap_index = swap_out (victim->kpage_addr);
    lock_acquire (&frame_table_lock);

    // Update the supplemental page table entry
    victim->current_sup_page->swap_index = swap_index;
    victim->current_sup_page->is_swapped = true;
  }

  pagedir_clear_page (victim->owner_thread->pagedir, spte->user_page);
  lock_release (&victim->owner_thread->supplemental_page_table_lock);

  free_frame_entry (victim);
}

/* Lookup frame by kernel page address. */
struct frame_table_entry * find_frame_entry (void *kpage)
{
  struct list_elem *e;
  
  lock_acquire (&frame_table_lock);
  for (e = list_begin (&frame_table); e != list_end (&frame_table); e = list_next (e))
  {
    struct frame_table_entry *entry = list_entry (e, struct frame_table_entry, elem);
    if (entry->kpage_addr == kpage)
    {
      lock_release (&frame_table_lock);
      return entry;
    }
  }
  
  lock_release (&frame_table_lock);
  return NULL;
}
