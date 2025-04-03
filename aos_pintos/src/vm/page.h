#include "../threads/palloc.h"
#include "../threads/malloc.h"
#include "../lib/kernel/list.h"
#include "../lib/debug.h"
#include "frame.h"
#include "../threads/synch.h"
#include "../userprog/pagedir.h"
#include "../threads/thread.h"

struct supplemental_page_table_entry{
    struct list_elem elem;

    void* pageAdress; 
    bool isFaulted;
    struct thread * owner;

};


