#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#define N_FRAMES ((4 << 20) / PGSIZE)

void frame_table_init(void);
void free_frame_table(void);

struct frame_table_entry {
    uint8_t frame_no;                   /* Records which frame the page is currently in. */
    void *upage;                        /* Pointer to the page that currently occupies the frame. */
    struct hash_elem frame_hash_elem;   /* Allows fte to be put into the hash frame_table. */
};

/* This might be a bad idea to not malloc as it will go on the kernel stack space */
struct frame_table {
    uint16_t max_frames;                 /* Maximum number of frames allowed in the frame table. */
    uint16_t num_frames;                 /* Current number of frames in use in the frame table. */
    struct hash ft;                      /* Hash to store all the frame_table_entries. */
};

void *frame_table_get_frame (void *upage, enum palloc_flags flags);
void frame_table_free_frame (void *kaddr);

#endif