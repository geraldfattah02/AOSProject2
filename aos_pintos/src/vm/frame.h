#ifndef __VM_FRAME_H
#define __VM_FRAME_H

struct frame_table_entry {
    struct list_elem elem;
    void* kpage_addr;
    struct thread * owner_thread;
    struct sup_page_table_entry *current_sup_page;
    bool pinned;
};

void init_frame_table (void);

void* allocate_frame (enum palloc_flags flags);
void free_frame (void * kpage);
void free_frame_entry (struct frame_table_entry *entry);
void pin_frame (void *page);
void unpin_frame (void *page);
void evict_page (void);

struct frame_table_entry *find_frame_entry (void *kpage);

#endif /* vm/frame.h */
