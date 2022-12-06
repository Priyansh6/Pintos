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
    struct lock fte_lock;               /* Frame table entry lock for eviction. */
    struct list owners;                 /* List of owners which contains the threads that are sharing this frame. */
    struct hash_elem frame_hash_elem;   /* Allows fte to be put into the hash frame_table. */
};

struct owner {
    struct thread *thread;
    struct list_elem elem;
};

struct lock ft_lock;                    /* Lock to allow for synchronisation on the frame table. */

void *frame_table_get_frame (void *upage, enum palloc_flags flags);
void frame_table_free_frame (void *kaddr);
struct frame_table_entry *get_frame_by_kpage (void *kpage);
struct owner *find_owner (struct list *owners);

#endif