#ifndef VM_PAGE
#define VM_PAGE

#include <hash.h>
#include "filesys/file.h"
#include "filesys/off_t.h"

#define MAX_USER_STACK_SIZE 0x400000

enum spt_entry_type {SWAP, FSYS, ZEROPAGE};

struct spt_entry {
    void *uaddr;                    /* Address in user virtual space of page. */
    enum spt_entry_type entry_type; /* SPT entries can be either SWAP, (if a page is held in swap space), 
                                       FSYS (if a page is held in the filesystem), or ZEROPAGE (since 
                                       zero pages should only be loaded into a frame just before they are written to).*/
    bool writable;                  
    union {
        struct {
            struct file *file;
            off_t ofs;
            uint32_t read_bytes;
            uint32_t zero_bytes;
        };
        size_t swap_slot;
    };
    struct hash_elem spt_hash_elem;
};

void free_spt_entry (struct hash_elem *elem, void *aux UNUSED);

void handle_user_page_fault (void *fault_addr);

unsigned spt_hash_func (const struct hash_elem *elem, void *aux UNUSED);
bool spt_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);

#endif