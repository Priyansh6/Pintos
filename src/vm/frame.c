#include <stdio.h>
#include "frame.h"
#include "threads/malloc.h"

static uintptr_t frame_number_from_kaddr (void *kaddr);

/* Wrapper around palloc_get_page() that also manages insertions
   and evictions from the frame table. */
void *
frame_table_get_frame (void *upage, enum palloc_flags flags)
{
    ASSERT (flags & PAL_USER);

    void *frame_addr = palloc_get_page (flags);

    uintptr_t frame_number = frame_number_from_kaddr (frame_addr);
  
    /* If we can't allocate any more pages, we need to choose a page to evict
       (and put it on the swap disk) to allow us to allocate another page. */
    if (frame_addr == NULL)
        PANIC ("aaaaah need to do eviction you fool\n");

    struct frame_table_entry *fte = (struct frame_table_entry *) malloc (sizeof (struct frame_table_entry));
    ASSERT (fte != NULL); // maybe need something stronger than an assert here

    fte->owner = thread_current ()->tid;
    fte->upage = upage;

    frame_table[frame_number] = fte;

    return frame_addr;
}

/* Frees the page at a particular frame. */
void 
frame_table_free_frame (void *kaddr)
{
    uintptr_t frame_number = frame_number_from_kaddr (kaddr);
    struct frame_table_entry *fte = frame_table[frame_number];
    palloc_free_page (ptov (frame_number));
    frame_table[frame_number] = NULL;
    free (fte);
}

/* Converts a kernel virtual address to a frame number by calling vtop and
   then discarding the offset bits (right-most PGBITS). */
static uintptr_t
frame_number_from_kaddr (void *kaddr) 
{
    return vtop (kaddr) >> PGBITS;
}