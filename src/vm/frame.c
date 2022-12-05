#include <stdio.h>
#include "frame.h"
#include "threads/malloc.h"
#include "hash.h"
#include "threads/synch.h"

static struct hash *frame_table;          /* Hash to store all the frame_table_entries. */
static uintptr_t frame_number_from_kaddr (void *kaddr);
static bool frame_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
unsigned frame_hash_func (const struct hash_elem *elem, void *aux UNUSED);
void free_frame_elem(struct hash_elem *e, void *aux UNUSED);

/* Initialises the frame table. */
void
frame_table_init (void)
{
    frame_table = (struct hash *) malloc (sizeof (struct hash));
    ASSERT (frame_table != NULL);

    hash_init(frame_table, frame_hash_func, frame_less, NULL);
    lock_init(&ft_lock);
}

/* Function for hasing the frame_no of a frame_table_enrty. */
unsigned 
frame_hash_func (const struct hash_elem *elem, void *aux UNUSED) {
    struct frame_table_entry *e = hash_entry (elem, struct frame_table_entry, frame_hash_elem);
    return hash_int ((int) e->frame_no);
}

/* Function for comparting two frame_table_entries. */
static bool 
frame_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
    const struct frame_table_entry *fte_a = hash_entry (a, struct frame_table_entry, frame_hash_elem);
    const struct frame_table_entry *fte_b = hash_entry (b, struct frame_table_entry, frame_hash_elem);

    return fte_a->frame_no < fte_b->frame_no;
}

/* Auxilliary function for freeing frame table at shutdown. */
void
free_frame_elem (struct hash_elem *e, void *aux UNUSED)
{
    struct frame_table_entry *fte = hash_entry(e, struct frame_table_entry, frame_hash_elem);
    free(fte);
}

/* Free frame table. */
void
free_frame_table (void)
{
    hash_destroy(frame_table , free_frame_elem);
    free(frame_table);
}

/* Wrapper around palloc_get_page() that also manages insertions
   and evictions from the frame table. */
void *
frame_table_get_frame (void *upage, enum palloc_flags flags)
{
    ASSERT (flags & PAL_USER);

    lock_acquire (&ft_lock);

    /* Attempting to allocate a page from memory. */
    void *frame_addr = palloc_get_page (flags);
  
    /* If we can't allocate any more pages, we need to choose a page to evict
       (and put it on the swap disk) to allow us to allocate another page. */
    if (frame_addr == NULL)
        PANIC ("aaaaah need to do eviction you fool\n");

    /* Creating new frame table entry on the heap. */
    struct frame_table_entry *fte = (struct frame_table_entry *) malloc (sizeof (struct frame_table_entry));
    ASSERT (fte != NULL);

    /* Inserting new page into frame table. */
    fte->upage = upage;
    fte->frame_no = frame_number_from_kaddr (frame_addr);
    hash_insert (frame_table, &fte->frame_hash_elem);

    lock_release (&ft_lock);
    return frame_addr;
}

/* Frees the page at a particular frame. */
void 
frame_table_free_frame (void *kaddr)
{
    struct frame_table_entry query;
    struct hash_elem *e;
    struct frame_table_entry *fte;

    /* Locating the frame to be freed in the frame table. */
    query.frame_no = frame_number_from_kaddr (kaddr);
    e = hash_find (frame_table, &query.frame_hash_elem);
    fte = hash_entry (e, struct frame_table_entry, frame_hash_elem);

    lock_acquire (&ft_lock);

    /* Freeing page from memory. */
    palloc_free_page (ptov (fte->frame_no));

    /* Removing page and freeing frame from frame table. */
    hash_delete (frame_table, e);
    free (fte);

    lock_release (&ft_lock);
}

/* Converts a kernel virtual address to a frame number by calling vtop and
   then discarding the offset bits (right-most PGBITS). */
static uintptr_t
frame_number_from_kaddr (void *kaddr) 
{
    return vtop (kaddr) >> PGBITS;
}