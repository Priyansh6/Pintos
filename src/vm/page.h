#ifndef VM_PAGE
#define VM_PAGE

#include <hash.h>
#include "filesys/file.h"
#include "filesys/off_t.h"

enum spt_entry_type {SWAP, FSYS, ZEROPAGE};

struct spt_entry {
    void *uaddr;
    enum spt_entry_type entry_type;
    union {
        struct {
            struct file *file;
            off_t ofs;
            uint32_t read_bytes;
            uint32_t zero_bytes;
            bool writable;
        };
    };
    struct hash_elem spt_hash_elem;
};

void free_spt_entry (struct hash_elem *elem, void *aux UNUSED);

void load_page_from_filesys (void);

unsigned spt_hash_func (const struct hash_elem *elem, void *aux UNUSED);
bool spt_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);

#endif