#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

/* There are 13 syscalls in task two. */
#define N_SYSCALLS 13
#define MAX_CONSOLE_BUFFER_OUTPUT 250
#define MIN(x, y) ((x <= y) ? x : y)

static void syscall_handler (struct intr_frame *);
static bool is_valid_user_ptr (void *uaddr);
static void get_args (const void *esp, void *args[], int num_args);
static bool validate_args (void *args[], int argc);
static void exit_failure (void);

static uint32_t exit_handler (void *args[]);
static uint32_t write_handler (void *args[]);
static uint32_t wait_handler (void *args[]);

static struct lock fs_lock;

/* Map from system call number to the corresponding handler */
static const struct syscall syscall_ptrs[] = {
  {.handler = &exit_handler, .argc = 1},
  {.handler = &exit_handler, .argc = 1},
  {.handler = &exit_handler, .argc = 1},
  {.handler = &wait_handler, .argc = 1},
  {.handler = &exit_handler, .argc = 1},
  {.handler = &exit_handler, .argc = 1},
  {.handler = &exit_handler, .argc = 1},
  {.handler = &exit_handler, .argc = 1},
  {.handler = &exit_handler, .argc = 1},
  {.handler = &write_handler, .argc = 3},
  {.handler = &exit_handler, .argc = 1},
  {.handler = &exit_handler, .argc = 1},
  {.handler = &exit_handler, .argc = 1},
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
get_args (const void *esp, void *args[], int num_args)
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
wait_handler (void *args[]) 
{
  tid_t *tid = args[0];
  return process_wait (*tid);
}

static uint32_t
write_handler (void *args[])
{

  int *fd = args[0];
  char **buffer = args[1];
  int *size = args[2];

  switch (*fd) {
    case 1:
      for (int i = 0; i < *size; i += MAX_CONSOLE_BUFFER_OUTPUT) {
        putbuf (*(buffer) + i, MIN(MAX_CONSOLE_BUFFER_OUTPUT, *size - i));
      }
      return *size;
    default:
      return 0;
  }

}
