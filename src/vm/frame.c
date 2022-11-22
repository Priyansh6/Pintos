#include <stdio.h>

#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"

#include "frame.h"

void *
frame_table_get_frame (void *upage)
{
    void * frame_addr =  palloc_get_page (PAL_USER);

    printf("%d\n", vtop (frame_addr));
    
    if (frame_addr == NULL) {
        PANIC ("aaaaah need to do eviction you fool\n");
    }

    struct frame_table_entry *fte = (struct frame_table_entry *) malloc (sizeof (struct frame_table_entry));
    ASSERT (fte != NULL); // maybe need something stronger than an assert here

    fte->owner = thread_current ()->tid;
    fte->upage = upage;

    frame_table[vtop (frame_addr)] = fte;

    return frame_addr;
}

void 
frame_table_free_frame ()
{

}

