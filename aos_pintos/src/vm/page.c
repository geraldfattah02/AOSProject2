/*
create supplemental page table 
get supplemental page
load a page into memory
delete page table entry from memory
*/


#include "vm/page.h"

struct supplemental_page_table_entry * get_supplemental_page_table_entry(void * virtualAddress)
{
    struct thread * current_thread = thread_current();
    struct list * supplemental_page_table = &current_thread->supplemental_page_table;


    struct list_elem *e;
    for (e = list_begin (&supplemental_page_table); e != list_end (&supplemental_page_table); e = list_next (e))
    {
        struct supplemental_page_table_entry *f = list_entry (e, struct supplemental_page_table_entry, elem);
        if (f->pageAdress == virtualAddress) {
            return f;
        }
    }
    return NULL;
}

//moved creation of the supplemental page to process.c in load_segment
// void * create_page(enum palloc_flags flags){
//     struct thread * current_thread = thread_current();
//     struct list * supplemental_page_table = &current_thread->supplemental_page_table;
//     struct lock * supplemental_page_table_lock = &current_thread->supplemental_page_table_lock;
//     void *frame =allocate_frame(flags); //physical address

//     struct supplemental_page_table_entry* page = malloc(sizeof(struct supplemental_page_table_entry));

//     //page ->pageAdress = frame;
//     page ->isFaulted = false;
//     page -> owner = thread_current();

//     lock_acquire(supplemental_page_table_lock);
//     list_push_back (supplemental_page_table, &page->elem);
//     lock_release(supplemental_page_table_lock);
//     return frame;
// }


void clear_supplemental_page_entries(struct list * page_table_entries){
     struct list_elem *e;
    for (e = list_begin (&page_table_entries); e != list_end (&page_table_entries); e = list_next (e))
    {
        struct supplemental_page_table_entry *f = list_entry (e, struct supplemental_page_table_entry, elem);
        free_frame(f->pageAdress);
        free(f);
    }
}



