#include "../threads/palloc.h"
#include "../threads/malloc.h"
#include "../lib/kernel/list.h"
#include "../lib/debug.h"
#include "frame.h"
#include "../threads/synch.h"
#include "../userprog/pagedir.h"
#include "../threads/thread.h"

struct lock frame_table_lock;
struct lock eviction_lock;
struct list frame_table;
struct list_elem *eviction_pointer = NULL;


void init_frame_table() {
    list_init (&frame_table);
    lock_init (&frame_table_lock);
    lock_init(&eviction_lock);
}

void* allocate_frame(enum palloc_flags flags) {
    void* page = palloc_get_page (flags);

    if (page == NULL) { // evict
        evict_page();
    }
    else { // Add to frame table
        struct frame_entry* frame = malloc(sizeof(struct frame_entry));

        frame->page_entry = page;
        frame->owner_thread = thread_current;

        lock_acquire (&frame_table_lock);
        list_push_back (&frame_table, &frame->elem);
        lock_release (&frame_table_lock);
    }  
    
    return page;
}

void evict_page() {
    //go through fram table list, chcek the accessed bit for each page, if true -> set to false,
    //iterate through until there is an accessed=true (recently accessed)
    lock_acquire(&frame_table_lock);
    struct frame_entry *victim = NULL;
    
    if (eviction_pointer == NULL || eviction_pointer == list_end(&frame_table)) {
        eviction_pointer = list_begin(&frame_table);
    }
    // Iterate using the eviction pointer
    while (victim == NULL) {
        if (eviction_pointer == list_end(&frame_table)) {
            eviction_pointer = list_begin(&frame_table);
        }
        
        struct frame_entry *f = list_entry(eviction_pointer, struct frame_entry, elem);
        
        if (!pagedir_is_accessed(f->owner_thread->pagedir, f->page_entry)) {
            victim = f;
        } else {
            pagedir_set_accessed(f->owner_thread->pagedir, f->page_entry, false);
        }
        
        eviction_pointer = list_next(eviction_pointer);
    }
    // Remove victim frame from table and free it
    list_remove(&victim->elem);
    palloc_free_page(victim->page_entry);
    free(victim);

    lock_release(&frame_table_lock);
}

void free_frame(void* page) {
    struct list_elem *e;

    lock_acquire (&frame_table_lock);
    for (e = list_begin (&frame_table); e != list_end (&frame_table); e = list_next (e))
    {
        struct frame_entry *f = list_entry (e, struct frame_entry, elem);
        if (f->page_entry == page) {
            list_remove (f);
            palloc_free_page (f->page_entry);
            free (f);
            break;
        }
    }
    lock_release (&frame_table_lock);
}