#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#define N_FRAMES ((4 << 20) / PGSIZE)

struct frame_table_entry {
    tid_t owner;
    void *upage;
};

/* This might be a bad idea to not malloc as it will go on the kernel stack space */
struct frame_table_entry *frame_table[N_FRAMES];

void *frame_table_get_frame (void *upage, enum palloc_flags flags);
void frame_table_free_frame (void *kaddr);

#endif