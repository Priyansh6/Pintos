#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "threads/malloc.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#define MAX_NUM_OF_CMD_LINE_ARGS 256
#define PUSH_STACK(type, pointer, value) pointer = ((type*) pointer) - 1; (*((type*) pointer) = (type) (value))

#define INITIAL_USER_PROCESS_TID 3

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static bool process_control_block_init (tid_t tid, int status);

void
init_process () 
{
  hash_init (&blocks, &block_hash, &tid_less, NULL);
  process_control_block_init (INITIAL_USER_PROCESS_TID, 0);
  
}

void
destroy_initial_process (void)
{
  struct process_control_block *block = get_pcb_by_tid (INITIAL_USER_PROCESS_TID);
  hash_delete (&blocks, &block->blocks_elem);
  hash_destroy (&blocks, NULL);
  free (block);
}

static bool
process_control_block_init (tid_t tid, int status)
{
  struct process_control_block *block = (struct process_control_block *) malloc (sizeof (struct process_control_block));
  if (block == NULL)
    return false;

  block->tid = tid;
  block->status = status;
  block->was_waited_on = false;
  block->next_fd = 2;
  sema_init (&block->wait_sema, 0);
  list_init (&block->children);
  list_init (&block->files);

  hash_insert (&blocks, &block->blocks_elem);

  return true;
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char **args;
  tid_t tid;

  /* Allocate a page of virtual memory for the arguments (so the total size of arguments are limited to 4KB). */
  args = palloc_get_page (0);
  if (args == NULL)
    return TID_ERROR;

  /* Make a copy of FILE_NAME, because we musn't modify file_name. */
  char *fn_copy = (char *) malloc ((1 + strlen (file_name)) * sizeof (char));
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);
  
  
  char *token, *save_ptr;
  int last = 0;
  
  /* Populate args array with each word in the command being run (file_name). */
  for (token = strtok_r (fn_copy, " ", &save_ptr); token != NULL; token = strtok_r (NULL, " ", &save_ptr), last++) {
    args[last] = (char *) malloc (sizeof (char) * (strlen (token) + 1));
    if (args[last] == NULL)
      return TID_ERROR;
    memcpy (args[last], token, strlen(token) + 1);
  }
  
  free (fn_copy);

  /* If last is 0 it means there were no tokens to process and so we should return an error state. */
  if (last == 0)
    return TID_ERROR;

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (args[0], PRI_DEFAULT, start_process, args);
  if (tid == TID_ERROR)
    palloc_free_page (args);

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char **args = file_name_;

  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (args[0], &if_.eip, &if_.esp);

  /* We use these variables to keep track of the original stack pointer
     address (esp_start) and to mark the address of the first character
     of the last argument pushed to the stack. These are used later in
     order to push pointers to the start of each argument to the stack. */
  char *esp_start = if_.esp;
  char *last_arg_start = if_.esp;

  /* First, push the arg strings onto the stack and free the memory
     allocated to them. */
     // TODO: what if we reach end of page
  int argc = 0;
  for (argc = 0; args[argc] != NULL; argc++) {
    last_arg_start -= (strlen(args[argc]) + 1);
    strlcpy (last_arg_start, args[argc], strlen(args[argc]) + 1);
    free (args[argc]);
  }

  /* Free the page allocated for the arguments. */
  palloc_free_page (args);

  /* Word align the stack. */
  int word_align = (esp_start - last_arg_start) % 4;
  if_.esp = last_arg_start - word_align;
  memset (if_.esp, 0, word_align);

  PUSH_STACK (char, if_.esp, '\0');

  /* Traverse back up the stack from last_arg_start until we reach esp_start 
     and push the address of the following element each time we encounter 
     a sentinel character. This pushes a pointer to the first character 
     of each argument. */
  char *word_start = last_arg_start;  

  while (last_arg_start++ != esp_start) {
    if (*last_arg_start == '\0') {
      PUSH_STACK (char *, if_.esp, word_start);
      word_start = last_arg_start + 1;
    }
  }

  /* Push argv, argc and return addres to the stack. */
  PUSH_STACK (char **, if_.esp, ((char **) if_.esp) + 1);
  PUSH_STACK (int, if_.esp, argc);
  PUSH_STACK (int, if_.esp, 0);

  if (thread_current ()->tid != INITIAL_USER_PROCESS_TID)
    process_control_block_init (thread_current ()->tid, -1);

  /* If load failed, quit. */
  if (!success)
    thread_exit ();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status. 
 * If it was terminated by the kernel (i.e. killed due to an exception), 
 * returns -1.  
 * If TID is invalid or if it was not a child of the calling process, or if 
 * process_wait() has already been successfully called for the given TID, 
 * returns -1 immediately, without waiting.
 * 
 * This function will be implemented in task 2.
 * For now, it does nothing. */
int
process_wait (tid_t child_tid) 
{
  struct process_control_block *child_pcb = get_pcb_by_tid (child_tid);

  if (child_pcb == NULL || child_pcb->was_waited_on)
    return -1;

  sema_down (&child_pcb->wait_sema);
  child_pcb->was_waited_on = true;

  return child_pcb->status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  struct process_control_block *pcb = get_pcb_by_tid (cur->tid);

  sema_up (&pcb->wait_sema);

  struct list_elem *e;

  // TODO: THINK ABOUT SYNCHRONIZATION
  enum intr_level old_level = intr_disable ();
  for (e = list_begin (&pcb->children); e != list_end (&pcb->children); e = list_next (e)) {
    struct process_control_block *child_pcb = list_entry (e, struct process_control_block, child_elem);
    hash_delete (&blocks, &child_pcb->blocks_elem);
    free (child_pcb);
  }
  intr_set_level (old_level);
  
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;
      
      /* Check if virtual page already allocated */
      struct thread *t = thread_current ();
      uint8_t *kpage = pagedir_get_page (t->pagedir, upage);
      
      if (kpage == NULL){
        
        /* Get a new page of memory. */
        kpage = palloc_get_page (PAL_USER);
        if (kpage == NULL){
          return false;
        }
        
        /* Add the page to the process's address space. */
        if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }     
        
      } else {
        
        /* Check if writable flag for the page should be updated */
        if(writable && !pagedir_is_writable(t->pagedir, upage)){
          pagedir_set_writable(t->pagedir, upage, writable); 
        }
        
      }

      /* Load data into the page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes){
        return false; 
      }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

/* Iterates over the process control blocks hash map and returns the entry 
   corresponding to a particular tid. Returns NULL if entry doens't exist. */
struct process_control_block *
get_pcb_by_tid (tid_t tid)
{
  struct process_control_block *pcb = (struct process_control_block *) malloc (sizeof (struct process_control_block));
  ASSERT (pcb != NULL);
  struct hash_elem *e;

  pcb->tid = tid;

  e = hash_find (&blocks, &pcb->blocks_elem);

  return e != NULL ? hash_entry (e, struct process_control_block, blocks_elem) : NULL;
}

/* Adds a file to a process's pcb as well as assigning it a file descriptor, which it returns. Returns -1 if fails */
/* TODO: Memory management */
int
pcb_add_file (struct process_control_block *pcb, struct file* file) {
  struct process_file *pfile = (struct process_file *) malloc (sizeof (struct process_file));
  if (pfile == NULL)
    return -1;

  int assigned_fd = pcb->next_fd++;
  pfile->fd = assigned_fd;
  pfile->file = file;
  list_push_back (&pcb->files, &pfile->list_elem);
  
  return assigned_fd;
}

/* Returns file_struct associated with file descriptor fd in the provided pcb */
struct file *
pcb_get_file (struct process_control_block *pcb, int fd)
{
  if (!list_empty (&pcb->files)) {
    struct list_elem *e;
    for (e = list_begin (&pcb->files); e != list_end (&pcb->files); e = list_next(e)) {
      struct process_file *pfile = list_entry (e, struct process_file, list_elem);
      if (pfile->fd == fd) {
        return pfile->file;
      }
      if (pfile->fd > fd) {
        return NULL;
      }
    }
  }
  return NULL;
}

/* Compares process_control_blocks on the basis of their associated tid. */
bool tid_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
  const struct process_control_block *pcb_a = hash_entry (a, struct process_control_block, blocks_elem);
  const struct process_control_block *pcb_b = hash_entry (b, struct process_control_block, blocks_elem);

  return pcb_a->tid < pcb_b->tid;
}

/* Hashes the tid field of a process control block*/
unsigned int block_hash (const struct hash_elem *elem, void *aux UNUSED) {
  const struct process_control_block *pcb = hash_entry (elem, struct process_control_block, blocks_elem);

  return hash_int (pcb->tid);
}