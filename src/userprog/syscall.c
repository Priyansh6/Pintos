#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "hash.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "vm/mmap.h"
#include "vm/page.h"

/* There are 15 syscalls in tasks two and three. */
#define N_SYSCALLS 15
#define MAX_CONSOLE_BUFFER_OUTPUT 250
#define MIN(x, y) ((x <= y) ? x : y)

static void syscall_handler (struct intr_frame *);
static bool is_valid_user_ptr (void *uaddr);
static void get_args (void *esp, void *args[], int num_args);
static void validate_args (void *args[], int argc);

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
static uint32_t mmap_handler (void *args[]);
static uint32_t munmap_handler (void *args[]);

/* Map from system call number to the corresponding handler. We also
   provide the expected argument count (used to validate arguments later on). */
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
  {.handler = &mmap_handler, .argc = 2},
  {.handler = &munmap_handler, .argc = 1},
};

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&fs_lock);
}

/* Finds which system call handler to execute from the provided interrupt frame, gets the 
   arguments from the frame, and puts the result of the system call handler into the eax
   register of the interrupt frame. */
static void
syscall_handler (struct intr_frame *f) 
{
  int *syscall_n = f->esp;
  if (is_valid_user_ptr (syscall_n) && *syscall_n >= 0 && *syscall_n < N_SYSCALLS) {
    struct syscall syscall = syscall_ptrs[*syscall_n];

    /* Get all arguments passed to system call from stack. */
    void *args[syscall.argc];
    get_args (f->esp, args, syscall.argc);

    /* Make sure that we can dereference all arguments safely. If any arguments
       are pointers (e.g char *) then we will need to validate these pointers
       separately in their respective system call handlers. 
       
       If any of the arguments fail validation, we exit the user program. */
    validate_args (args, syscall.argc);

    /* Make call to corresponding system call handler and put the return value 
       in the eax register. It's okay to do this even when we don't expect a return
       value because nothing else will inspect/require the contents of the eax register. */
    f->eax = syscall.handler (args);
  } else {
    exit_failure ();
  }
}

/* Gracefully exits the user program with status -1. Should be called
   in the event of an error (e.g user attempts to pass a NULL argument to 
   system call or attempts to derefence a NULL pointer themselves.) */
void
exit_failure (void)
{
  int status = -1;
  void *args[1] = {&status};
  exit_handler (args);
}

/* Populates the args array with the arguments passed to the syscall
   which are stored on the stack. We don't (at this point) know the type
   of each argument but we do know that each argument is a pointer. Since
   all pointers are of the same size, we can traverse up the stack by the size
   of a pointer to get each argument. */
static void
get_args (void *esp, void *args[], int num_args)
{
  for (int i = 0; i < num_args; i++)
    args[i] = esp + (sizeof(void *) * (i + 1));
}

/* Verifies that: (i) uaddr is not null, (ii) address is within the user memory space
   and (iii) that the address maps to a valid page. */
static bool 
is_valid_user_ptr (void *uaddr)
{
  return (uaddr) && is_user_vaddr (uaddr) && !get_spt_entry_by_uaddr (uaddr);
}

/* Every argument that the uses passes is a pointer - this function
   goes through each byte of each pointer to verify that we can
   dereference it (by a call to is_valid_user_ptr). */
static void
validate_args (void *args[], int argc)
{
  for (int i = 0; i < argc; i++) {
    if (!is_valid_user_ptr (args[i]))
      exit_failure ();
  }
}

/* Calls exit failure if fd is greater than highest_invalid_fd. */
static void
assert_fd_greater_than (int fd, int highest_invalid_fd)
{
  if (fd <= highest_invalid_fd)
    exit_failure ();
}

/* Checks if provided file descriptor is valid (greater than 0) and calls exit_failure
   if it isn't. */
static void
assert_valid_fd (int fd)
{
  assert_fd_greater_than (fd, -1);
}

/* Immediately shutsdown PintOS. */
static uint32_t
halt_handler (void *args[] UNUSED)
{
  shutdown_power_off();
  thread_exit ();
  /* Should never get here. */
  return 0;
}

/* Sets the return status of the current process' PCB to
   the status code passed by the user and exits the currently
   running process. */
static uint32_t
exit_handler (void *args[]) 
{
  int *status_code = args[0];
  process_set_status_code (*status_code);
  printf ("%s: exit(%d)\n", thread_current()->name, *status_code);
  thread_exit ();
  return 0;
}

/* Creates a new process which runs the executable given by
   the user (filename). 
   
   We must not return from this until we are sure that the executable
   has fully and successfully loaded. This is handled by the load_sema
   on the process' PCB. */
static uint32_t
exec_handler(void *args[]) 
{
  /* Verify that we can dereference the filename string. */
  const char **filename = args[0];
  if (!is_valid_user_ptr ((char *) *filename))
    exit_failure ();

  tid_t child_tid = process_execute (*filename);
  
  if (child_tid == TID_ERROR)
    return TID_ERROR;

  return process_wait_on_load (child_tid);
}

/* Makes the currently running process wait for one of
   it's child processes to finish executing. */
static uint32_t
wait_handler (void *args[]) 
{
  tid_t *tid = args[0];
  return process_wait (*tid);
}

/* Creates a file on the PintOS file system. */
static uint32_t 
create_handler (void *args[])
{
  /* Verify that we can dereference the file string. */
  const char **file = args[0];
  if (!is_valid_user_ptr ((char *) *file))
    exit_failure ();

  off_t *initial_size = args[1];

  lock_acquire(&fs_lock);
  bool success = filesys_create(*file, *initial_size);
  lock_release(&fs_lock);
  return success;

}

/* Removes a file from the PintOS file system. */
static uint32_t 
remove_handler (void *args[])
{
  /* Verify that we can dereference the file string. */
  const char **file = args[0];
  if (!is_valid_user_ptr ((char *) *file))
    exit_failure ();

  lock_acquire (&fs_lock);
  bool result = filesys_remove (*file);
  lock_release (&fs_lock);
  return result;
}

/* Opens a file and returns -1 if it fails. */
static uint32_t 
open_handler (void *args[])
{
  /* Verify that we can dereference the file string. */
  const char **file = args[0];
  if (!is_valid_user_ptr ((char *) *file))
    exit_failure ();
  
  lock_acquire (&fs_lock);
  struct file *opened_file = filesys_open(*file);
  if (opened_file == NULL) {
    lock_release (&fs_lock);
    return -1;
  }

  int fd = process_add_file (opened_file);
  
  if (fd < 0) {
    file_close (opened_file);
    lock_release (&fs_lock);
    return -1;
  }

  lock_release (&fs_lock);
  return fd;
}

/* Returns the filesize, in bytes, of a given file. */
static uint32_t 
filesize_handler (void *args[])
{
  int *fd = args[0];
  assert_fd_greater_than (*fd, 1);

  struct file *file = process_get_file (*fd);
  if (file == NULL)
    exit_failure ();

  lock_acquire (&fs_lock);
  uint32_t length = file_length (file);
  lock_release (&fs_lock);
  return length;
}

/* Reads size bytes from the file open as fd into buffer. 

   Returns the number of bytes actually
   read (0 at end of file), or -1 if the file could not be read (due to a condition other than
   end of file). */
static uint32_t 
read_handler (void *args[])
{
  int *fd = args[0];
  char **buffer = args[1];
  uint32_t *size = args[2];
  assert_valid_fd (*fd);

  /* Verify that we can dereference the buffer. */
  if (!is_valid_user_ptr ((char *) *buffer))
    exit_failure ();

  switch (*fd) {
    case 0:
      /* Read from user input device (i.e keyboard). */
      for (uint32_t i = 0; i < *size; i++)
        *buffer[i] = input_getc ();
      return *size;
    case 1:
      /* Reserved for writing to STDOUT. */
      exit_failure ();
      return 0;
    default: ;
      /* Read from a file on the file system into the buffer.*/
      struct file *file = process_get_file (*fd);
      if (file == NULL)
        exit_failure ();

      lock_acquire (&fs_lock);
      uint32_t bytes_read = file_read (file, *buffer, *size);
      lock_release (&fs_lock);
      return bytes_read;
  }
}

/* Writes size bytes from buffer to the open file fd. Returns the number of bytes actually
   written, which may be less than size if some bytes could not be written. */
static uint32_t
write_handler (void *args[])
{
  int *fd = args[0];
  char **buffer = args[1];
  uint32_t *size = args[2];
  assert_valid_fd (*fd);

  /* Verify that we can dereference the buffer. */
  if (!is_valid_user_ptr ((char *) *buffer))
    exit_failure ();

  switch (*fd) {
    case 0:
      /* Reserved for reading from STDIN. */
      exit_failure ();
      return 0;
    case 1:
      /* Write the contents of the buffer to STDOUT. */
      lock_acquire (&fs_lock);
      for (uint32_t i = 0; i < *size; i += MAX_CONSOLE_BUFFER_OUTPUT)
        putbuf (*(buffer) + i, MIN(MAX_CONSOLE_BUFFER_OUTPUT, *size - i));
      lock_release (&fs_lock);
      return *size;
    default: ;
      struct file *file = process_get_file (*fd);
      if (file == NULL)
        exit_failure ();

      /* Write the contents of the buffer to a file. */
      lock_acquire (&fs_lock);
      uint32_t bytes_written = file_write (file, *buffer, *size);
      lock_release (&fs_lock);
      return bytes_written;
  }
}

/* Changes the next byte to be read or written in open file fd to position, expressed in bytes
   from the beginning of the file. */
static uint32_t 
seek_handler (void *args[])
{
  int *fd = args[0];
  uint32_t *position = args[1];

  struct file *file = process_get_file (*fd);
  if (file == NULL)
    exit_failure ();

  lock_acquire (&fs_lock);
  file_seek (file, *position);
  lock_release (&fs_lock);
  return 0;
}

/* Returns the position of the next byte to be read or written in open file fd, expressed in bytes
   from the beginning of the file.*/
static uint32_t 
tell_handler (void *args[]) 
{
  int *fd = args[0];
  struct file *file = process_get_file (*fd);
  if (file == NULL)
    exit_failure ();

  lock_acquire (&fs_lock);
  uint32_t position = file_tell (file);
  lock_release (&fs_lock);
  return position;
}

/* Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open file
   descriptors, as if by calling this function for each one. */
static uint32_t 
close_handler (void *args[])
{
  int *fd = args[0];
  assert_fd_greater_than (*fd, 1);

  struct file *file = process_get_file (*fd);
  if (file == NULL)
    exit_failure ();

  process_remove_file (*fd);
  return 0;
}

static uint32_t
mmap_handler (void *args[])
{
  int *fd = args[0];
  assert_fd_greater_than (*fd, 1);

  uint32_t *addr = args[1];

  return (uint32_t) mmap_create (*fd, (void *) *addr);
}

static uint32_t
munmap_handler (void *args[])
{
  int *mapping = args[0];
  mmap_unmap (*mapping);
  return 0;
}

bool
safe_acquire_fs_lock (void) {
  if (lock_held_by_current_thread (&fs_lock)) 
    return false;
  
  lock_acquire (&fs_lock);
  return true;
}

void
safe_release_fs_lock (bool should_release_lock) {
  if (should_release_lock)
    lock_release (&fs_lock);
}
