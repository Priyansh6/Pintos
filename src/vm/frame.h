#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "hash.h"

#define N_FRAMES ((4 << 20) / PGSIZE)

void frame_table_init(void);
void free_frame_table(void);

struct frame_table_entry {
    void *kpage;                        /* Records which frame the page is currently in. */
    void *upage;                        /* Pointer to the page that currently occupies the frame. */
    struct list owners;
    struct hash_elem frame_hash_elem;   /* Allows fte to be put into the hash frame_table. */
};

struct owner {
    struct thread *thread;
    struct list_elem elem;
};

/* This might be a bad idea to not malloc as it will go on the kernel stack space */
struct frame_table {
    uint16_t max_frames;                 /* Maximum number of frames allowed in the frame table. */
    uint16_t num_frames;                 /* Current number of frames in use in the frame table. */
    struct hash ft;                      /* Hash to store all the frame_table_entries. */
    struct lock ft_lock;                 /* Lock to allow for synchronisation on the frame table. */
};

void *frame_table_get_frame (void *upage, enum palloc_flags flags);
void frame_table_free_frame (void *kaddr);
struct frame_table_entry *get_frame_by_kpage (void *kpage);

#endif