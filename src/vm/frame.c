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
static struct frame_table_entry *choose_victim2 (void);
static void remove_and_invalidate_owners (struct frame_table_entry *fte);
static struct spt_entry *prepare_spt_entry_for_eviction (void *uaddr);
static void evict_page (struct spt_entry *page, void *kpage);

static struct hash_iterator RR_frame_index;

/* Initialises the frame table. */
void
frame_table_init (void)
{
  hash_init (&frame_table, frame_hash_func, frame_less, NULL);
  hash_first (&RR_frame_index, &frame_table);
  lock_init (&ft_lock);
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
    /* Getting a frame to be evicted. */
    fte = choose_victim2 ();

    /* Invalidate the page table entries for this frame for all owners. 
       Must be done in a lock to prevent others adding or removing themselves 
       mid-eviction. */
    remove_and_invalidate_owners (fte);

    /* Get the spage table entry. Creates an spt entry if one does not already exist,
       and removes it from the share table if the page is shareable. */
    struct spt_entry *page = prepare_spt_entry_for_eviction (fte->upage);

    /* Evict the page. */
    evict_page (page, fte->kpage);
    
  } else {
    /* Creating new frame table entry on the heap. */
    fte = (struct frame_table_entry *) malloc (sizeof (struct frame_table_entry));
    ASSERT (fte != NULL);

    /* Inserting new page into frame table. */
    fte->kpage = frame_addr;
    hash_insert (&frame_table, &fte->frame_hash_elem);
    list_init (&fte->owners);
    lock_init (&fte->fte_lock);
  }

  /* Set the user address which points to the frame. */
  fte->upage = upage;
  
  /* Add ourselves as an owner of the frame. */
  struct owner *owner = (struct owner *) malloc (sizeof (struct owner));
  ASSERT (owner != NULL);
  owner->thread = thread_current ();
  list_push_back (&fte->owners, &owner->elem);

  lock_release (&ft_lock);
  return fte->kpage;
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
  struct owner *owner = list_entry (list_pop_front (&fte->owners), struct owner, elem);
  free (owner);
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

/* Removes all owners of the given frame and invalidates their page table
   entries. */
static void 
remove_and_invalidate_owners (struct frame_table_entry *fte) 
{
  struct list_elem *e;
  for (e = list_begin (&fte->owners); e != list_end (&fte->owners); ) {
    struct owner *o = list_entry (e, struct owner, elem);
    ASSERT (o != NULL);

    /* Invalidate owner's page table entry that points to this frame. */
    pagedir_clear_page (o->thread->pagedir, fte->upage);

    /* Remove owners from list. */
    list_remove (e);

    /* Before we free the owner, get the next list elem. */
    e = list_next (e);
    free (o);
  }
}

/* Prepares a supplemental page table entry for eviction: if the entry doesn't exist,
   for example in the case of a stack page, then we create one. If the entry indicates
   that the page is read only, then we remove it from the share table as well. */
static struct spt_entry *
prepare_spt_entry_for_eviction (void *uaddr)
{
  struct spt_entry *page = get_spt_entry_by_uaddr (uaddr);

  /* If we don't have a spage table entry (i.e stack page) then we create one. */
  if (page == NULL) {
    page = (struct spt_entry *) malloc (sizeof (struct spt_entry));

    if (page == NULL)
      PANIC ("no idea what to do here tbh");

    page->uaddr = uaddr;
    page->entry_type = SWAP;
    page->writable = true;

    hash_insert (&thread_current ()->spt, &page->spt_hash_elem);
  }

  /* Remove the page from the shared table. */
  if (!page->writable) {
    lock_acquire (&shared_table_lock);

    struct shared_file *s_file = get_shared_file (file_get_inode (page->file));
    struct shared_file_page *s_page = get_shared_page (s_file, page->ofs);

    hash_delete (&s_file->shared_pages_table, &s_page->elem);
    free (s_page);

    lock_release (&shared_table_lock);
  }
  return page;
}

static void
evict_page (struct spt_entry *page, void *kpage)
{
  switch (page->entry_type) {
    case FSYS:
      if (page->writable) {
        /* This page is not shared by any other processes so we just need to put the page
          on the swap disk and update our own SPT. */
        page->entry_type = SWAP;
        page->swap_slot = swap_out (kpage);
      } else {
        /* Read only page. This page could be shared, but we have already removed
          all owners from the frame and updated their page tables. Also, all SPT
          will already have all the information to load the page back in if needed
          so we don't need to do anything here. */
      }
      break;
    case ZEROPAGE:
      if (pagedir_is_dirty (thread_current ()->pagedir, page->uaddr)) {
        /* The page has been written to, so we need to update our SPT to change the page entry type
          and also put our page on the swap disk. It is not a shared page as we only share read only pages. */
        page->entry_type = SWAP;
        page->swap_slot = swap_out (kpage);
      } else {
        /* The page has not been written to and is still a zeropage. It *could* be shared, but
          this wouldn't matter as if it were, it would be read only and so we know that no other
          process has written to it. */
      }
      break;
    case SWAP:
      /* All we need to do here is place the page on the swap disk and update our own SPT entry
        to provide information on where exactly we place the page within the disk. */
      page->entry_type = SWAP;
      page->swap_slot = swap_out (kpage);
      break;
  }

  /* The page has now been swapped out, so we must update the in_memory flag our our SPT entry. */
  page->in_memory = false;
}

struct frame_table_entry *
get_frame_by_kpage (void *kpage)
{
  struct frame_table_entry query = {.kpage = kpage};
  lock_acquire (&ft_lock);
  struct hash_elem *e = hash_find (&frame_table, &query.frame_hash_elem);
  lock_release (&ft_lock);
  return e == NULL ? NULL : hash_entry (e, struct frame_table_entry, frame_hash_elem);
}

/* Sets all owner threads for a frame table entry to not accessed. */
static void
set_owners_not_accessed (struct frame_table_entry *fte)
{
  struct list_elem *e;
  for (e = list_begin (&fte->owners); e != list_end (&fte->owners); e = list_next (e))
  {
    struct owner *o = list_entry (e, struct owner, elem);
    ASSERT (o != NULL);

    pagedir_set_accessed(o->thread->pagedir, fte->upage, false);
  }
}

/* Checks if any owner thread in the frame table has been accessed. */
static bool
any_owner_accessed (struct frame_table_entry *fte)
{
  struct list_elem *e;

  for (e = list_begin (&fte->owners); e != list_end (&fte->owners); e = list_next (e))
  {
    struct owner *o = list_entry (e, struct owner, elem);
    ASSERT (o != NULL);

    if (pagedir_is_accessed(o->thread->pagedir, fte->upage)) {
      pagedir_set_accessed(o->thread->pagedir, fte->upage, false);
      return true; 
    }
  }

  return false;
}

/* Second Chance Algorithm for finding a frame to evict. */
static struct frame_table_entry *
choose_victim2 (void) 
{
  /* Infinitely looping until we find a frame to evict. */
  while (true)
    {
      /* If we are at the end of the frame table and we havent found a frame to evict, loop back to the start. */
      if (hash_next (&RR_frame_index) == NULL)
        hash_first (&RR_frame_index, &frame_table); 

      struct frame_table_entry *f = hash_entry (hash_cur (&RR_frame_index), struct frame_table_entry, frame_hash_elem);
      ASSERT (f != NULL);

      /* Check if this frame f has been accessed by any of its owners. If it has been accessed, set the accessed bits to 
         false and move on. Otherwise, we have found our frame to evict so we return it, breaking out the loop. */
      if (!any_owner_accessed (f))
        return f;
      set_owners_not_accessed (f);
    }
  
  /* Should never get here. */
  return NULL;
}
