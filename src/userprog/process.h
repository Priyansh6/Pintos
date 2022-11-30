#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "filesys/file.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "vm/page.h"
#include "hash.h"
#include "list.h"

struct process_control_block;

void init_process (void);
void process_set_status_code (int status_code);
tid_t process_execute (const char *file_name);
tid_t process_wait_on_load (tid_t);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

struct process_control_block *process_get_pcb (void);
struct process_control_block *process_control_block_init (tid_t tid);
void pcb_set_parent (struct process_control_block *child, struct process_control_block *parent);
struct process_control_block *pcb_get_child_by_tid (tid_t child_tid);
int process_add_file (struct file* file);
struct file *process_get_file (int fb);
bool process_remove_file (int fd);
void process_destroy_files (void);
bool process_file_set_mapping (int fd, struct spt_entry *spt);
struct spt_entry *process_file_get_mapping (int fd);

#endif /* userprog/process.h */
