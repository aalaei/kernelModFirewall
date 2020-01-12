#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>


#define DEVICE_NAME "hooker_dev"

int main(int argc,char * argv[]){
  int allow=2;
  char msg_buff[1000];
  char file_path[100];
  char line[100][50];
  char path[50];
  int line_cnt=0;
  
  sprintf(path,"/dev/%s",DEVICE_NAME);
  FILE * f;
  if(argc!=2)
  {
    printf("please enter config file path:\n");
    scanf("%s",file_path);
  }else{
    strcpy(file_path,argv[1]);
  }
  f=fopen(file_path,"r");
  if(f==NULL)
  {
    printf("file dosen't exits!!\n");
    return -1;
  }
  char *res;
  char typeOfService[50];

  res=fgets(typeOfService,50,f);
  typeOfService[strlen(typeOfService)-1]=0;
  do
  {
    res=fgets(line[line_cnt],50,f);
    //line[line_cnt][strlen(line[line_cnt])-1]=0;
    line_cnt++;
  } while (res!=NULL);
  
  do{
    line_cnt--;
  }while(strcmp(line[line_cnt-1]," \n")==0 || strcmp(line[line_cnt-1],"\n")==0);
  
  if(strcmp(typeOfService,"whitelist")==0)
  {
    allow=1;
  }else if(strcmp(typeOfService,"blacklist")==0)
    allow=0;
  //fprintf(f,"%s\n%s:%s",msg_buff);
  for(int i=0;i<line_cnt;i++)
  {
    printf("%d: %s\n",i,line[i]);
  }
  
  int dev = open(path,O_RDWR);
  if (dev<0)
    printf("error openning the device\n");
  //sprintf(msg_buff, "first msg to kernel##");
  sprintf(msg_buff, "%d\n",allow);
  for(int i=0;i<line_cnt;i++)
  {
    strcat(msg_buff,"#");
  }
  strcat(msg_buff,"\n");
  for(int i=0;i<line_cnt;i++)
  {
    //printf("%d: %s\n",i,line[i]);
    strcat(msg_buff,line[i]);
    
  }
  write(dev, msg_buff, strlen(msg_buff)+1);
  printf("%s\nset",msg_buff);

  // char buff[1000];
  // read(dev, buff, 100);
  // printf("reading a buffer from kernel module :%s\n", buff);


  // sprintf(msg_buff, "second msg to kernel");
  // write(dev, msg_buff, strlen(msg_buff)+1);

  // bzero(buff, 1000);
  // read(dev, buff, 100);
  // printf("reading a buffer from kernel module :%s\n", buff);
  close(dev);

}
