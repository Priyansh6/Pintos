#include <stdio.h>
#include "frame.h"
#include "threads/malloc.h"
#include "hash.h"
#include "threads/synch.h"
#include "vm/page.h"

static struct hash *frame_table;          /* Hash to store all the frame_table_entries. */
static struct owner *find_owner (struct list *owners);
static bool frame_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
static unsigned frame_hash_func (const struct hash_elem *elem, void *aux UNUSED);
static void free_frame_elem (struct frame_table_entry *fte);
static void hash_free_frame_elem (struct hash_elem *e, void *aux UNUSED);

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
static unsigned 
frame_hash_func (const struct hash_elem *elem, void *aux UNUSED) {
    struct frame_table_entry *e = hash_entry (elem, struct frame_table_entry, frame_hash_elem);
    return hash_int ((int) e->kpage);
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
    hash_destroy (frame_table, hash_free_frame_elem);
    free (frame_table);
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
    fte->kpage = frame_addr;
    hash_insert (frame_table, &fte->frame_hash_elem);
    list_init (&fte->owners);

    struct owner *owner = (struct owner *) malloc (sizeof (struct owner));
    ASSERT (owner != NULL);
    owner->thread = thread_current ();
    list_push_back (&fte->owners, &owner->elem);

    lock_release (&ft_lock);
    return frame_addr;
}

/* Frees the page at a particular frame. */
void 
frame_table_free_frame (void *kaddr)
{
    lock_acquire (&ft_lock);

    struct frame_table_entry query = {.kpage = kaddr};
    struct hash_elem *e = hash_find (frame_table, &query.frame_hash_elem);
    struct frame_table_entry *fte = e == NULL ? NULL : hash_entry (e, struct frame_table_entry, frame_hash_elem);

    /* -------------------------------------------------- */

    ASSERT (e != NULL);


    struct spt_entry *spage_entry = get_spt_entry_by_uaddr (fte->upage);

    if (spage_entry != NULL && spage_entry->entry_type == FSYS && !spage_entry->writable) {

        //printf("Freeing shared frame on thread %d corresponding to inode %p with offset %d and user address %p.\n", thread_current ()->tid, file_get_inode (spage_entry->file), spage_entry->ofs, spage_entry->uaddr);
        //printf("WRITTABLE: %d\n", spage_entry->writable);

        // We have to be careful here because we could be dealing with a shared frame.
        //
        // We only want to free the frame if we are the sole owner of it. In this case
        //      we also want to free our shared_file_page entry. If after doing so, there are
        //      no more entries in the shared_file_pages table, then we can free and destroy the table.
        //      We will leave the freeing of the shared_file table entry to be done when we close the file
        //      (the freeing is only done if we are the sole sharer of the file, otherwise we just decrement the number of sharers).
        //
        // Otherwise, we just remove ourselves as an owner of the frame.

        struct shared_file *file = get_shared_file (file_get_inode (spage_entry->file));
        struct shared_file_page *page = get_shared_page (file, spage_entry->ofs);

        if (file != NULL && page != NULL) {

            if (list_size (&fte->owners) > 1) {
                /* Other processes are using this frame, so we cannot free it. */
                struct owner *owner = find_owner (&fte->owners);
                list_remove (&owner->elem);
                free (owner);
                lock_release (&ft_lock);
                return;
            }

            /* If we reach this point, no other processes are using this frame so we
               can safely free it. We also need to remove the shared_file_page entry. */
            hash_delete (&file->shared_pages_table, &page->elem);
            free (page);

            if (hash_empty (&file->shared_pages_table)) {
                hash_destroy (&file->shared_pages_table, NULL);
                hash_delete (&shared_file_table, &file->elem);
                free (file);
            }

        }

    }

    /* -------------------------------------------------- */

    /* Removing page and freeing frame from frame table. */
    hash_delete (frame_table, e);
    free_frame_elem (fte);

    lock_release (&ft_lock);

}

static struct owner *
find_owner (struct list *owners)
{
    struct list_elem *e;
    for (e = list_begin (owners); e != list_end (owners); e = list_next (e)) {
      struct owner *owner = list_entry (e, struct owner, elem);
      if (owner->thread->tid == thread_current ()->tid)
        return owner;
    }
    return NULL;
}

struct frame_table_entry *
get_frame_by_kpage (void *kpage)
{
    struct frame_table_entry query = {.kpage = kpage};
    struct hash_elem *e = hash_find (frame_table, &query.frame_hash_elem);

    return e == NULL ? NULL : hash_entry (e, struct frame_table_entry, frame_hash_elem);
}



