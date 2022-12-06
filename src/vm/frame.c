#include <stdio.h>
#include "hash.h"
#include "list.h"
#include "devices/swap.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/share.h"

static struct hash frame_table;          /* Hash to store all the frame_table_entries. */
static bool frame_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
static unsigned frame_hash_func (const struct hash_elem *elem, void *aux UNUSED);
static void free_frame_elem (struct frame_table_entry *fte);
static void hash_free_frame_elem (struct hash_elem *e, void *aux UNUSED);
static struct frame_table_entry *choose_victim (void);

/* Initialises the frame table. */
void
frame_table_init (void)
{
  hash_init(&frame_table, frame_hash_func, frame_less, NULL);
  lock_init(&ft_lock);
}

/* Function for hasing the frame_no of a frame_table_enrty. */
static unsigned 
frame_hash_func (const struct hash_elem *elem, void *aux UNUSED) 
{
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
  hash_destroy (&frame_table, hash_free_frame_elem);
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

  struct frame_table_entry *fte;

  /* If we can't allocate any more pages, we need to choose a page to evict
      (and put it on the swap disk) to allow us to allocate another page. */
  if (frame_addr == NULL) {
    ASSERT (false);
    /* Getting a frame to be evicted. */
    fte = choose_victim ();
    
    ASSERT (fte != NULL);

    //lock_acquire (&fte->fte_lock);
    //lock_release (&ft_lock);

    /* Invalidate the page table entries for this frame for all owners. 
       Must be done in a lock to prevent others adding or removing themselves 
       mid-eviction. */
    struct list_elem *e;
    for (e = list_begin (&fte->owners); e != list_end (&fte->owners); e = list_next (e)) {
        struct owner *o = list_entry (e, struct owner, elem);
        ASSERT (o != NULL);
        pagedir_clear_page (o->thread->pagedir, fte->upage);

        /* Move page into swap or filesys depending on spt type. */
        struct spt_entry spt_query = {.uaddr = fte->upage};
        struct hash_elem *he = hash_find (&o->thread->spt, &spt_query.spt_hash_elem);

        struct spt_entry *spt = hash_entry (he, struct spt_entry, spt_hash_elem);
        ASSERT (spt != NULL);
        ASSERT (spt->in_memory);
        switch (spt->entry_type) {
          case ZEROPAGE:
          case FSYS:
            if (pagedir_is_dirty (o->thread->pagedir, spt->uaddr)) {
              spt->entry_type = SWAP;
            } else {
              break;
            }
          case SWAP:
            spt->swap_slot = swap_out (fte->kpage); // we should only do this for the first thing - otherwise we just copy the swap slot to spt entries
            break;
        }

        spt->in_memory = false;

        /* Remove owners from list. */
        list_remove (e);
    }
    
    //lock_release (&fte->fte_lock);
  } else {
    /* Inserting new page into frame table. */
    /* Creating new frame table entry on the heap. */
    fte = (struct frame_table_entry *) malloc (sizeof (struct frame_table_entry));
    ASSERT (fte != NULL);
    hash_insert (&frame_table, &fte->frame_hash_elem);
    list_init (&fte->owners);
  }

  fte->upage = upage;
  fte->kpage = frame_addr;

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
  struct hash_elem *e = hash_find (&frame_table, &query.frame_hash_elem);
  struct frame_table_entry *fte = e == NULL ? NULL : hash_entry (e, struct frame_table_entry, frame_hash_elem);
  //lock_acquire (&fte->fte_lock);

  if (free_shared_page (fte)) {
    //lock_release (&fte->fte_lock);
    lock_release (&ft_lock);
    return;
  }

  //lock_release (&fte->fte_lock);
  /* Removing page and freeing frame from frame table. */
  hash_delete (&frame_table, e);
  free_frame_elem (fte);
  lock_release (&ft_lock);
}

struct owner *
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
  struct hash_elem *e = hash_find (&frame_table, &query.frame_hash_elem);

  return e == NULL ? NULL : hash_entry (e, struct frame_table_entry, frame_hash_elem);
}

static int frame_to_evict = 0;

/* Iterates through frame_table and chooses frame to evict. */
static struct frame_table_entry *
choose_victim (void) 
{
  
  frame_to_evict = frame_to_evict % hash_size (&frame_table);
  
  int c = 0;
  struct hash_iterator i;

  hash_first (&i, &frame_table);
  while (hash_next (&i))
    {
      c++;
      struct frame_table_entry *f = hash_entry (hash_cur (&i), struct frame_table_entry, frame_hash_elem);
      if (frame_to_evict == c || c == (int) hash_size (&frame_table)) {
        frame_to_evict++;
        return f;
      }
    }
  return NULL;
}



bool
any_owner_accessed (struct frame_table_entry *fte)
{
  struct list_elem *e;

  for (e = list_begin (&fte->owners); e != list_end (&fte->owners); e = list_next (e))
  {
    struct owner *o = list_entry (e, struct owner, elem);
    if (pagedir_is_accessed(o->thread->pagedir, fte->upage)) {
      pagedir_set_accessed(o->thread->pagedir, fte->upage, false);
      return true; 
    }
  }

  return false;
}

static struct hash_iterator RR_frame_index;

static struct frame_table_entry *
choose_victim2 (void) 
{
  //initial implementation of Second Change algorithm
  hash_first (&RR_frame_index, &frame_table);

  while (hash_next (&RR_frame_index))
    {
      struct frame_table_entry *f = hash_entry (hash_cur (&RR_frame_index), struct frame_table_entry, frame_hash_elem);
      if (!any_owner_accessed(f))
        return f;
    }
  return NULL;
}
