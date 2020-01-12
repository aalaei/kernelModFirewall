#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

int main(){
  char msg_buff[1000];
  int dev = open("/dev/hooker_dev",O_RDWR);
  if (dev<0)
    printf("error openning the device\n");

  char buff[1000];
  read(dev, buff, 100);
  printf("reading a buffer from kernel module :%s\n", buff);

  // sprintf(msg_buff, "second msg to kernel");
  // write(dev, msg_buff, strlen(msg_buff)+1);

  // bzero(buff, 1000);
  // read(dev, buff, 100);
  // printf("reading a buffer from kernel module :%s\n", buff);
  close(dev);
}
