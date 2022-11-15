#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "hash.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"

/* There are 13 syscalls in task two. */
#define N_SYSCALLS 13
#define MAX_CONSOLE_BUFFER_OUTPUT 250
#define MIN(x, y) ((x <= y) ? x : y)

static void syscall_handler (struct intr_frame *);
static bool is_valid_user_ptr (void *uaddr);
static void get_args (void *esp, void *args[], int num_args);
static bool validate_args (void *args[], int argc);
static void exit_failure (void);

static struct file *get_file (int fd);
static bool remove_file (int fd);
static void assert_fd_greater_than (int fd, int highest_invalid_fd);
static void assert_valid_fd (int fd);

static uint32_t halt_handler(void *args[]);
static uint32_t exit_handler (void *args[]);
static uint32_t exec_handler(void *args[]);
static uint32_t wait_handler (void *args[]);
static uint32_t create_handler (void *args[]);
static uint32_t remove_handler (void *args[]);
static uint32_t open_handler (void *args[]);
static uint32_t filesize_handler (void *args[]);
static uint32_t read_handler (void *args[]);
static uint32_t write_handler (void *args[]);
static uint32_t seek_handler (void *args[]);
static uint32_t tell_handler (void *args[]);
static uint32_t close_handler (void *args[]);

static struct lock fs_lock;

/* Map from system call number to the corresponding handler */
static const struct syscall syscall_ptrs[] = {
  {.handler = &halt_handler, .argc = 0},
  {.handler = &exit_handler, .argc = 1},
  {.handler = &exec_handler, .argc = 1},
  {.handler = &wait_handler, .argc = 1},
  {.handler = &create_handler, .argc = 2},
  {.handler = &remove_handler, .argc = 1},
  {.handler = &open_handler, .argc = 1},
  {.handler = &filesize_handler, .argc = 1},
  {.handler = &read_handler, .argc = 3},
  {.handler = &write_handler, .argc = 3},
  {.handler = &seek_handler, .argc = 2},
  {.handler = &tell_handler, .argc = 1},
  {.handler = &close_handler, .argc = 1},
};

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&fs_lock);
}

static void
syscall_handler (struct intr_frame *f) 
{
  int *syscall_n = f->esp;
  if (is_valid_user_ptr (syscall_n) && *syscall_n >= 0 && *syscall_n < N_SYSCALLS) {
    struct syscall syscall = syscall_ptrs[*syscall_n];

    /* Get all arguments passed to system call from stack. */
    void *args[syscall.argc];
    get_args (f->esp, args, syscall.argc);

    /* Make sure that we can dereference all arguments safely. */
    if (!validate_args (args, syscall.argc))
      exit_failure ();
    
    /* Make call to corresponding system call handler and put the return value 
       in the eax register. It's okay to do this even when we don't expect a return
       value because nothing else will inspect/require the contents of the eax register. */
    f->eax = syscall.handler (args);
  } else {
    exit_failure ();
  }
}

/* If the user provides an invalid system call number, we handle 
   it gracefully by terminating the user thread. */
static void
exit_failure (void)
{
  int status = -1;
  void *args[1] = {&status};
  exit_handler (args);
}

static void
get_args (void *esp, void *args[], int num_args)
{
  for (int i = 0; i < num_args; i++)
    args[i] = esp + (sizeof(void *) * (i + 1));
}

static bool 
is_valid_user_ptr (void *uaddr)
{
  return uaddr && is_user_vaddr (uaddr) && pagedir_get_page (thread_current ()->pagedir, uaddr);
}

static bool
validate_args (void *args[], int argc)
{
  for (int i = 0; i < argc; i++) {
    if (!is_valid_user_ptr (args[i]))
      return false;
  }
  return true;
}

static void
free_hash_elem(struct hash_elem *e, void *aux UNUSED)
{
  struct process_control_block *pcb = hash_entry (e, struct process_control_block, blocks_elem);
  free(pcb);
}

static uint32_t
halt_handler (void *args[] UNUSED)
{
  //free all entries in blocks hash table and the table itself
  hash_destroy(&blocks, free_hash_elem);

  //shutdown pintos
  shutdown_power_off();
  destroy_initial_process ();
  thread_exit ();
  //should never get here
  return 0;
}

static uint32_t
exit_handler (void *args[]) 
{
  int *status_code = args[0];

  get_pcb_by_tid (thread_current ()->tid)->status = *status_code;

  printf ("%s: exit(%d)\n", thread_current()->name, *status_code);
  thread_exit ();
  return 0;
}

static uint32_t
exec_handler(void *args[]) 
{
 // if (!is_valid_user_ptr ((const char **) args[0]))
 //   return -1;
  
  tid_t tid = process_execute (*((const char **) args[0]));
  struct process_control_block *pcb = get_pcb_by_tid (tid);
  sema_down (&pcb->load_sema);
  return pcb->has_loaded ? tid : -1;
}

static uint32_t
wait_handler (void *args[]) 
{
  tid_t *tid = args[0];
  return process_wait (*tid);
}

//creates a new file on the filesys
//NOT TESTED
static uint32_t 
create_handler (void *args[])
{
  char **file = args[0];
  off_t *initial_size = args[1];

  //locking across file system
  if (is_valid_user_ptr(*file)) {
    lock_acquire(&fs_lock);
    bool success = filesys_create(*file, *initial_size);
    lock_release(&fs_lock);
    return success;
  } else {
    exit_failure();
    return 0;
  }
}

static uint32_t 
remove_handler (void *args[])
{
  char ** filename = args[0];
  lock_acquire (&fs_lock);
  bool result = filesys_remove (*filename);
  lock_release (&fs_lock);
  return result;
}

/* Gets file with file decriptor fd from the current running process's process
   control block. Calls exit_failure if a file was not found. */
static struct file *
get_file (int fd) {
  struct process_control_block *pcb = get_pcb_by_tid (thread_current ()->tid);
  struct file *file = pcb_get_file (pcb, fd);
  if (file == NULL)
    exit_failure ();
  return file;
}

/* Removes file with file descriptor fd from the current running process's process
   control block and frees it from memory. Returns whether a file was removed. */
static bool
remove_file (int fd) {
  struct process_control_block *pcb = get_pcb_by_tid (thread_current ()->tid);
  return pcb_remove_file (pcb, fd);
}

/* Calls exit failure if fd is greater than highest_invalid_fd. */
static void
assert_fd_greater_than (int fd, int highest_invalid_fd) {
  if (fd <= highest_invalid_fd)
    exit_failure ();
}

/* Checks if provided file descriptor is valid (greater than 0) and calls exit_failure
   if it isn't. */
static void
assert_valid_fd (int fd) {
  assert_fd_greater_than (fd, -1);
}

static uint32_t 
open_handler (void *args[])
{
  char **file = args[0];
  if (*file == NULL)
    return -1;
  
  struct file *opened_file = filesys_open(*file);
  if (opened_file == NULL)
    return -1;

  struct process_control_block *pcb = get_pcb_by_tid (thread_current ()->tid);
  int fd = pcb_add_file (pcb, opened_file);
  if (fd < 0)
    file_close (opened_file);

  return fd;
}

static uint32_t 
filesize_handler (void *args[])
{
  int *fd = args[0];
  assert_fd_greater_than (*fd, 1);

  struct file *file = get_file (*fd);
  return file_length (file);
}

static uint32_t 
read_handler (void *args[])
{
  int *fd = args[0];
  char **buffer = args[1];
  uint32_t *size = args[2];
  assert_valid_fd (*fd);

  switch (*fd) {
    case 0:
      for (uint32_t i = 0; i < *size; i++) {
        *buffer[i] = input_getc ();
      }
      return *size;
    case 1:
      exit_failure ();
      return 0;
    default:
      return file_read (get_file(*fd), *buffer, *size);
  }
}

static uint32_t
write_handler (void *args[])
{
  int *fd = args[0];
  char **buffer = args[1];
  uint32_t *size = args[2];
  assert_valid_fd (*fd);

  switch (*fd) {
    case 0:
      exit_failure ();
      return 0;
    case 1:
      for (uint32_t i = 0; i < *size; i += MAX_CONSOLE_BUFFER_OUTPUT) {
        putbuf (*(buffer) + i, MIN(MAX_CONSOLE_BUFFER_OUTPUT, *size - i));
      }
      return *size;
    default:
      return file_write (get_file(*fd), *buffer, *size);
  }
}

static uint32_t 
seek_handler (void *args[])
{
  int *fd = args[0];
  uint32_t *position = args[1];

  struct file *file = get_file (*fd);
  file_seek (file, *position);
  return 0;
}

static uint32_t 
tell_handler (void *args[]) 
{
  int *fd = args[0];

  struct file *file = get_file (*fd);
  return file_tell (file);
}

static uint32_t 
close_handler (void *args[])
// TODO: CLOSE ALL FILES ASSOCIATED WITH PROCESS WHEN IT EXITS
{
  int *fd = args[0];
  assert_fd_greater_than (*fd, 1);

  remove_file (*fd);
  return 0;
}
