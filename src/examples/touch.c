#include <stdio.h>
#include <syscall.h>

int
main (int argc, char **argv)
{
  create (argv[1], 128);
  return 0;
}
