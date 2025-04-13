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
struct lock frame_table_lock;
struct lock eviction_lock;
struct list frame_table;
struct list_elem *eviction_pointer = NULL;


void init_frame_table (void)
{
    list_init (&frame_table);
    lock_init (&frame_table_lock);
    lock_init(&eviction_lock);
}

void* allocate_frame (enum palloc_flags flags) 
{
    lock_acquire(&frame_table_lock);
    void* page = palloc_get_page (flags);

    if (page == NULL) { // evict
        evict_page ();
        // return allocate_frame(flags); //once we evict, call function again and there should be space now
        page = palloc_get_page (flags);
    }

    ASSERT (page != NULL);
    
    struct frame_table_entry* frame = malloc(sizeof(struct frame_table_entry));
    if (frame == NULL)
    {
        lock_release (&frame_table_lock);
        set_exit_code (thread_current (), -1);
        thread_exit ();
    }

    frame->kpage_addr = page;
    frame->owner_thread = thread_current();
    frame->pinned = false;

    DPRINT ("Allocating frame %p for %p\n", page, thread_current());

    //lock_acquire (&frame_table_lock);
    list_push_back (&frame_table, &frame->elem);
    lock_release (&frame_table_lock);
    
    return frame;
}

void free_frame_entry (struct frame_table_entry *entry)
{
    list_remove (&entry->elem);
    palloc_free_page (entry->kpage_addr);
    free (entry);
}

static void free_frame_no_lock (void* page)
{
    struct list_elem *e;
    bool found = false;
    for (e = list_begin (&frame_table); e != list_end (&frame_table); e = list_next (e))
    {
        struct frame_table_entry *f = list_entry (e, struct frame_table_entry, elem);
        if (f->kpage_addr == page && f->owner_thread == thread_current ()) {
            DPRINT ("Freed frame for %p, thread %p\n", page, thread_current ());
            found = true;
            free_frame_entry (f);
            break;
        }
    }
    if (!found) PANIC ("No frame for %p, thread %p\n", page, thread_current ());
}

void evict_page ()
{
    //go through fram table list, chcek the accessed bit for each page, if true -> set to false,
    //iterate through until there is an accessed=true (recently accessed)
    // lock_acquire(&frame_table_lock);
    struct frame_table_entry *victim = NULL;
    
    if (eviction_pointer == NULL || eviction_pointer == list_end(&frame_table)) {
        eviction_pointer = list_begin(&frame_table);
        struct frame_table_entry *f = list_entry(eviction_pointer, struct frame_table_entry, elem);
        victim = f;
    }
    DPRINT ("Starting eviction\n");
    // Iterate using the eviction pointer
    while (true) {
        if (eviction_pointer == list_end(&frame_table)) {
            eviction_pointer = list_begin(&frame_table);
        }

        struct frame_table_entry *f = list_entry(eviction_pointer, struct frame_table_entry, elem);
        eviction_pointer = list_next(eviction_pointer);  // advance for next iteration

        if (f->pinned) continue;

        struct sup_page_table_entry *spte = f->current_sup_page;
        DPRINT ("Page Entry: %p\n",f->kpage_addr);
        DPRINT ("Page Directory: %p\n",f->owner_thread->pagedir);
        DPRINT ("Spte page adress: %p\n",spte->user_page);
        DPRINT ("Current %p\n", thread_current());
        DPRINT ("Owner %p\n", f->owner_thread);
        if(spte != NULL){
            if (!pagedir_is_accessed(f->owner_thread->pagedir, spte->user_page)) {
                victim = f;
                DPRINT ("Not Accessed\n");
                break;
            } else {
                pagedir_set_accessed(f->owner_thread->pagedir, spte->user_page, false);
                DPRINT ("Setting Access to Zero\n");
            }
        }else{
            continue;
        }
    }
    
    // Remove victim frame from table and free it
    struct sup_page_table_entry *spte = victim->current_sup_page;
    DPRINT ("Checking dirty bit\n");
    // Check if the page is dirty and swap it out if necessary
    if (pagedir_is_dirty(victim->owner_thread->pagedir, spte->user_page) || spte->page_type == PAGE_CHANGED) {
        DPRINT ("Is dirty\n");
        // Swap out the page
        spte->page_type = PAGE_CHANGED;
        swap_index_t swap_index = swap_out(victim->kpage_addr);
        DPRINT ("Swapped out\n");

        //update the supplemental page table entry
        DPRINT ("victim %p\n", victim);
        DPRINT ("victim spte %p\n", victim->current_sup_page);
        victim->current_sup_page->swap_index = swap_index;
        victim->current_sup_page->is_swapped = true;

        DPRINT ("Swap done\n");
    }

    pagedir_clear_page(victim->owner_thread->pagedir, spte->user_page);

    free_frame_no_lock(victim->kpage_addr);
    //lock_release(&frame_table_lock);

}

void free_frame (void* page)
{

    lock_acquire (&frame_table_lock);
    free_frame_no_lock(page);
    lock_release (&frame_table_lock);
}

struct frame_table_entry * find_frame_entry (void *kpage)
{
  struct list_elem *e;
  
  lock_acquire (&frame_table_lock);
  for (e = list_begin (&frame_table); e != list_end (&frame_table); e = list_next (e))
  {
    struct frame_table_entry *entry = list_entry(e, struct frame_table_entry, elem);
    if (entry->kpage_addr == kpage)
    {
      lock_release (&frame_table_lock);
      return entry;
    }
  }
  
  lock_release (&frame_table_lock);
  return NULL;
}

void pin_frame(void *kpage)
{
    lock_acquire(&frame_table_lock);
    struct frame_table_entry *entry = find_frame_entry(kpage);
    if (entry != NULL)
        entry->pinned = true;
    lock_release(&frame_table_lock);
}

void unpin_frame(void *kpage)
{
    lock_acquire(&frame_table_lock);
    struct frame_table_entry *entry = find_frame_entry(kpage);
    if (entry != NULL)
        entry->pinned = false;
    lock_release(&frame_table_lock);
}
