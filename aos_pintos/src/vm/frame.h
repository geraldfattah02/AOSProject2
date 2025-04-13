#ifndef __VM_FRAME_H
#define __VM_FRAME_H

struct frame_entry {
    void* page_entry;
    struct list_elem elem;
    struct thread * owner_thread;
    struct supplemental_page_table_entry * supplemental_page_table_entry;
    bool pinned;
};

void init_frame_table();

void* allocate_frame(enum palloc_flags flags);
void free_frame(void * page);
void pin_frame(void *page);
void unpin_frame(void *page);
void* evict_page(void);

#endif /* vm/frame.h */
