#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
int main(void){
  printf("SUID_AT_EXEC uid=%d euid=%d\n", getuid(), geteuid()); fflush(stdout);
  setuid(0);
  printf("SUID_AFTER_SETUID uid=%d euid=%d\n", getuid(), geteuid()); fflush(stdout);
  int fd=open("/proc/sys/kernel/core_pattern", O_WRONLY);
  if(fd<0){perror("open");return 2;}
  write(fd,"|/bin/true",10); close(fd);
  printf("SUID_WRITE_DONE\n"); fflush(stdout);
  sleep(12); return 0;
}
