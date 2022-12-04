#include <stdio.h>
#include "frame.h"
#include "threads/malloc.h"
#include "hash.h"
#include "threads/synch.h"

static struct frame_table *frame_table;
static bool frame_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
static unsigned frame_hash_func (const struct hash_elem *elem, void *aux UNUSED);
static void free_frame_elem (struct frame_table_entry *fte);
static void hash_free_frame_elem (struct hash_elem *e, void *aux UNUSED);

/* Initialises the frame table. */
void
frame_table_init (void)
{
    frame_table = (struct frame_table *) malloc (sizeof (struct frame_table));
    ASSERT (frame_table != NULL);

    frame_table->max_frames = N_FRAMES;
    frame_table->num_frames = 0;
    hash_init(&frame_table->ft, frame_hash_func, frame_less, NULL);
    lock_init(&frame_table->ft_lock);
}

/* Function for hasing the frame_no of a frame_table_enrty. */
static unsigned 
frame_hash_func (const struct hash_elem *elem, void *aux UNUSED) {
    struct frame_table_entry *e = hash_entry (elem, struct frame_table_entry, frame_hash_elem);
    return hash_int ((int) (e->kpage));
}

/* Function for comparting two frame_table_entries. */
static bool 
frame_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
    const struct frame_table_entry *fte_a = hash_entry (a, struct frame_table_entry, frame_hash_elem);
    const struct frame_table_entry *fte_b = hash_entry (b, struct frame_table_entry, frame_hash_elem);

    return (int) fte_a->kpage < (int) fte_b->kpage;
}

/* Frees a frame table entry and frees associated frame */
static void
free_frame_elem (struct frame_table_entry *fte)
{
    palloc_free_page (fte->kpage);
    frame_table->num_frames--;
    free(fte);
}

/* Auxilliary function for freeing frame table at shutdown. */
static void 
hash_free_frame_elem (struct hash_elem *e, void *aux UNUSED) {
    struct frame_table_entry *fte = hash_entry(e, struct frame_table_entry, frame_hash_elem);
    free_frame_elem (fte);
}

/* Free frame table. */
void
free_frame_table (void)
{
    hash_destroy(&frame_table->ft, hash_free_frame_elem);
    free(frame_table);
}

/* Wrapper around palloc_get_page() that also manages insertions
   and evictions from the frame table. */
void *
frame_table_get_frame (void *upage, enum palloc_flags flags)
{
    ASSERT (flags & PAL_USER);

    lock_acquire (&frame_table->ft_lock);

    /* Attempting to allocate a page from memory. */
    void *frame_addr = palloc_get_page (flags);
  
    /* If we can't allocate any more pages, we need to choose a page to evict
       (and put it on the swap disk) to allow us to allocate another page. */
    if (frame_addr == NULL || frame_table->num_frames >= frame_table->max_frames)
        PANIC ("aaaaah need to do eviction you fool\n");

    /* Creating new frame table entry on the heap. */
    struct frame_table_entry *fte = (struct frame_table_entry *) malloc (sizeof (struct frame_table_entry));
    ASSERT (fte != NULL);

    /* Inserting new page into frame table. */
    fte->upage = upage;
    fte->kpage = frame_addr;
    hash_insert (&frame_table->ft, &fte->frame_hash_elem);

    frame_table->num_frames++;

    lock_release (&frame_table->ft_lock);
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
    lock_acquire (&frame_table->ft_lock);
    query.kpage = kaddr;
    e = hash_find (&frame_table->ft, &query.frame_hash_elem);

    if (e) {
        fte = hash_entry (e, struct frame_table_entry, frame_hash_elem);

        /* Removing page and freeing frame from frame table. */
        hash_delete (&frame_table->ft, e);
        free_frame_elem (fte);
    }

    lock_release (&frame_table->ft_lock);
}