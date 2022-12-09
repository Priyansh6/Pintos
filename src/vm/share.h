#ifndef VM_SHARE
#define VM_SHARE

#include <hash.h>
#include "filesys/file.h"
#include "threads/synch.h"
#include "vm/frame.h"

struct lock shared_table_lock;

struct shared_file {
    struct inode *file_inode;                   /* Pointer to the shared file inode. (Key) */
    struct hash shared_pages_table;             /* Shared pages hash map. */
    struct hash_elem elem;
};

struct shared_file_page {
    uint32_t page_offset;                       /* Offset of page within the shared file (Key) */
    struct frame_table_entry *frame_entry;      /* Pointer to the frame currently loaded in to memory. */
    struct hash_elem elem;
};

void init_shared_file_table (void);
struct shared_file *get_shared_file (struct inode *file_inode);
struct shared_file_page *get_shared_page (struct shared_file *file, uint32_t page_offset);
void insert_shared_page (struct inode *file_inode, uint32_t page_offset, void *kpage);

bool free_shared_page (struct frame_table_entry *fte);

unsigned inode_hash_func (const struct hash_elem *elem, void *aux UNUSED);
bool inode_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);

unsigned offset_hash_func (const struct hash_elem *elem, void *aux UNUSED);
bool offset_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);

void free_shared_file_elem (struct hash_elem *e, void *aux UNUSED);
void free_shared_table (void);

#endif