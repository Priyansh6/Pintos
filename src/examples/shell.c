#include <stdio.h>
#include <syscall.h>

#define ENTER_KEY 13
#define DELETE 127

int
main (void) 
{
  printf("\e[1;1H\e[2J");
  while (true) {

    char cmd[128] = "";
    int size = 0;
    
    printf("pintos-shell@lucas:~$ ");
    while (size < 127) {
        char c[1];
        read (0, c, 1);

        switch ((int) c[0]) {
          case ENTER_KEY:
            goto exit;
          case DELETE:
            cmd[--size] = '\0';
            printf("\b \b");
            break;
          default:
            printf("%c", c[0]);
            cmd[size] = c[0];
            size++; 
            break;
        }

          
    }
    exit:
      printf("\n");
      cmd[size + 1] = '\0';
      wait (exec (cmd));

  }
  
  return 0;
}
