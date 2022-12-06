#include <stdio.h>
#include <syscall.h>
#include <string.h>

#define ENTER_KEY 13
#define DELETE 127
#define EXIT 27

int
main (int argc, char *argv[])
{
  // Clear the screen
  printf("\e[1;1H\e[2J");

  // Read file into buffer
  int fd = open (argv[1]);

  char buffer[1024];
  read (fd, buffer, 256);

  printf("%s\n", buffer);

  int cursor = strlen (buffer);

  printf("%d\n", cursor);

  while (true) {
    char c[1];
    read (0, c, 1);

    switch ((int) c[0]) {
      case ENTER_KEY:
        printf("\n");
        buffer[cursor] = '\n';
        cursor++;
        break;
      case EXIT:
        printf("\n");
        goto exit;
        break;
      case DELETE:
        buffer[--cursor] = '\0';
        printf("\b \b");
        break;
      default:
        printf("%c", c[0]);
        buffer[cursor] = c[0];
        cursor++; 
        break;
    }
  }

  exit:
  printf("%d\n", cursor);
  printf("%s\n", buffer);
  write (fd, buffer, cursor);
  close (fd);

  return 0;
}
