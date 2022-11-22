#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/thread.h"

#define N_FRAMES (1 << 20)

struct frame_table_entry {
    tid_t owner;
    void *upage;
};

struct frame_table_entry *frame_table[N_FRAMES];

void *frame_table_get_frame (void *upage);
void frame_table_free_frame ();



#endif