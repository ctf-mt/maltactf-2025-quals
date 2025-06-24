#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

typedef struct {
  size_t idx;
  uint8_t data[16];
} Packet;

int main() {
  int fd = open("/dev/dwarf", O_RDWR);
  printf("fd = %d\n", fd);

  int status = ioctl(fd, 0x12, 0);
  printf("status = %d\n", status);
}