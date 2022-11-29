#include <stdio.h>
#include "frame.h"
#include "threads/malloc.h"
#include "hash.h"

static struct frame_table *frame_table;
static uintptr_t frame_number_from_kaddr (void *kaddr);
static bool frame_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
unsigned frame_hash_func (const struct hash_elem *elem, void *aux UNUSED);
void free_frame_elem(struct hash_elem *e, void *aux UNUSED);

/* Initialises the frame table. */
void
frame_table_init (void)
{
    frame_table = (struct frame_table *) malloc (sizeof (struct frame_table));
    frame_table->max_frames = N_FRAMES;
    frame_table->num_frames = 0;
    hash_init(&frame_table->ft, frame_hash_func, frame_less, NULL);
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

/* Auxilliary function for freeing frame table. */
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
    hash_destroy(&frame_table->ft, free_frame_elem);
    free(frame_table);
}

/* Wrapper around palloc_get_page() that also manages insertions
   and evictions from the frame table. */
void *
frame_table_get_frame (void *upage, enum palloc_flags flags)
{
    ASSERT (flags & PAL_USER);

    void *frame_addr = palloc_get_page (flags);
  
    /* If we can't allocate any more pages, we need to choose a page to evict
       (and put it on the swap disk) to allow us to allocate another page. */
    if (frame_addr == NULL || frame_table->num_frames >= frame_table->max_frames)
        PANIC ("aaaaah need to do eviction you fool\n");

    struct frame_table_entry *fte = (struct frame_table_entry *) malloc (sizeof (struct frame_table_entry));
    ASSERT (fte != NULL); // maybe need something stronger than an assert here

    fte->upage = upage;
    fte->frame_no = frame_number_from_kaddr (frame_addr);
    hash_insert(&frame_table->ft, &fte->frame_hash_elem);

    frame_table->num_frames++;

    return frame_addr;
}

/* Frees the page at a particular frame. */
void 
frame_table_free_frame (void *kaddr)
{
    struct frame_table_entry query;
    struct hash_elem *e;
    struct frame_table_entry *fte;

    query.frame_no = frame_number_from_kaddr(kaddr);
    e = hash_find(&frame_table->ft, &query.frame_hash_elem);
    fte = hash_entry(e, struct frame_table_entry, frame_hash_elem);

    palloc_free_page (ptov (fte->frame_no));

    hash_delete(&frame_table->ft, e);
    frame_table->num_frames--;
    free (fte);
}

/* Converts a kernel virtual address to a frame number by calling vtop and
   then discarding the offset bits (right-most PGBITS). */
static uintptr_t
frame_number_from_kaddr (void *kaddr) 
{
    return vtop (kaddr) >> PGBITS;
}