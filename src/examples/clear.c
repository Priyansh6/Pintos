#include <stdio.h>
#include <syscall.h>

int
main (void) 
{
  printf("\e[1;1H\e[2J");
  return 0;
}
