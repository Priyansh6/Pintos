#include "hash.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "vm/mmap.h"
#include "vm/page.h"

mapid_t mmap_create (int fd, void *uaddr) 
{
    /* Check that file mapped by fd has non-zero length
        and has already been opened by the process. */
    struct file *file = process_get_file (fd);
    if (file == NULL || file_length (file) == 0)
        return -1;

    /* Check uaddr is page aligned and is not 0. */
    if (uaddr == 0 || pg_ofs (uaddr) != 0)
        return -1;

    /* Calculate number of pages required to mmap the file, rounding up. */
    int n_pages = (file_length (file) + (PGSIZE - 1)) / PGSIZE;

    /* Check mmapped file doesn't overlap any existing set of mapped 
        pages (including lazy loaded executables). */
    for (int i = 0; i < n_pages; i++) {
        struct spt_entry spt;
        spt.uaddr = uaddr;

        struct hash_elem *e = hash_find (&thread_current ()->spt, &spt.spt_hash_elem);
        if (e != NULL)
            return -1;
    }

    /* Check mmapped file won't overlap with user stack. */
    if (uaddr + PGSIZE * n_pages > PHYS_BASE - MAX_USER_STACK_SIZE)
        return -1;

    /* mmap the whole file by seeking to the beginning. */
    file_seek (file, 0);

    uint32_t left_to_map = file_length (file);
    for (int i = 0; i < n_pages; i++) {
        struct spt_entry *page = (struct spt_entry *) malloc (sizeof (struct spt_entry));

        page->writable = true; // this seems okay for now, maybe we will need to make this dependent on a file's deny_write field
        page->uaddr = uaddr + PGSIZE * i;
        page->entry_type = FSYS;
        page->file = file;
        page->ofs = PGSIZE * i;

        uint32_t map_bytes = left_to_map < PGSIZE ? left_to_map : PGSIZE;
        page->read_bytes = map_bytes;
        page->zero_bytes = PGSIZE - map_bytes;

        ASSERT (hash_insert (&thread_current()->spt, &page->spt_hash_elem) == NULL);

        left_to_map -= map_bytes;
    }


    process_file_set_mapped (fd, true);

    return fd;
}

void mmap_unmap (mapid_t mapping) 
{
    // Do we need to exit_failure() if the mapping doesn't exist?
    // If we do, maybe this needs to be done in the syscall handler before we call this function
    process_file_set_mapped (mapping, false);
}