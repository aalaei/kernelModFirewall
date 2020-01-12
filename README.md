
# firewall kernel module
**Name: Sayed Ali Alaei TabaTabaei
Student number: 9530403**

This is Document of linux kernelmodule + app_writer program

appwriter will ask for configuration path and load the config file into kernel module
we have 2 types of configuration files : 1.balck list 2.white list


# Description of user mode program(app writer)

It is an ordinary program first it check if there is any config file path as input argument otherwise it request the path from user.
after beeing able to open configuration file it's time to call our kernel module!
"**hooker_dev**" is name of our device we want to open and write configuration
to it.
first we get typeOfService and then lines of configuration
one example config file:
```sh
whitelist
192.168.43.200:80
192.168.43.1:8888
192.168.43.1:80
```
if first line matches "whitelist" then allow variable is true else false.
after parsing the file it is written in msg_buff variable
example:
```sh
1
###
192.168.43.200:80
192.168.43.1:8888
192.168.43.1:80
```
note number of # symbol is equal to number of lines!
so the above message is passed to our kernel Module
# Lets see What our Kernel Module does!

first we have some info:
```sh
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ali alaei");
MODULE_DESCRIPTION("A simple network Linux module.");
MODULE_VERSION("1.00");
static char * name ="fireWall";
module_param(name, charp, S_IRUGO);
MODULE_PARM_DESC(name, "The name to display in /var/log/kern.log");
#define DEVICE_NAME "hooker_dev"
#define CLASS_NAME "hooker_class"
#define BUF_LEN  256
```
wich can be seen by kerinfo
next we have some variables:
```sh
static int Major;
static int Device_Open = 0;
static char kernel_buffer[BUF_LEN];

static int buff_len = 0;
static struct class*  charClass;
```
major is kernel driver's majoir number
Device_Open is number of times that devices is opend and not closed!
// **Note:** we have a mutex called "char_mutex" that do not allow an user app to open it when it is busy so Device_Open is 1 at most!!
we do the above mutex to solve that probable conflict (two user apps write configure to kernel module!)

next:
```sh
static int device_open(struct inode *inode, struct file *filp);
static int device_release(struct inode *inode, struct file *filp);
static ssize_t device_write(struct file *filp, const char *buf, size_t len, loff_t *off);

static struct file_operations fops = {
  .write = device_write,
  .open = device_open,
  .release = device_release
};
```
these are open release and write functions that user program calls!
and we have some other axilary variables:
```sh
struct sk_buff *sock_buff; //socket buffer
struct iphdr *ip_header; // ip header
struct udphdr *udph; // udp header
//struct tcphdr *tcph; //tcp header
char ip_address[16]; // ip address
u16 portNum;  //port number
int allow=2; // 0>black list /1>white list
char ips[100][16]; // ips which we are intrested in!
u16 ports[100];  //ports  which we are intrested in!
int numOfFilter=0; // number of records in config file!
```
Only one important note: ip and port addresses of tcp and udp reside on the same offset address so I commented all parts related to TCP and treat them just like UDP
but you can uncommnet it if you want

# Initialization of  hooker
```c
unsigned int hooker(unsigned int hooknum, struct sk_buff *skb,
                       const struct net_device *in, const struct net_device *out,
                       int(*okfn)(struct sk_buff *));


static struct nf_hook_ops packet_drop __read_mostly = {
        .pf = NFPROTO_IPV4,
        .priority = NF_IP_PRI_FIRST,
        .hooknum =NF_INET_LOCAL_IN,
        .hook = (nf_hookfn *) hooker
};
```
- 1. hook number is level of messege process (in which state of process this function should be handled!)
- 2. sk_buff is soucket buffer
- 3. 'in' and 'out' are input and output devices in net device format
- 4. okfn is pointer to function for handling final action of hooker
 
 now lets Go on with functions implementation
 # init function
```c
int ret;
  printk(KERN_INFO "Hello %s\n",name);

  Major = register_chrdev(0, DEVICE_NAME, &fops);

  if (Major < 0) {
    printk(KERN_ALERT "Registering char device failed with %d\n", Major);
    return Major;
  }
  printk(KERN_ALERT "Char device Registerd with  %d\n", Major);
```
as above we request major number from kernel since we want to reduce conflict probability as least as possible !
if every thing goes well we log "Char device Registerd with MAJORNUMBER"

now we go to making new class:
```c
charClass = class_create(THIS_MODULE, CLASS_NAME);
  if(IS_ERR(charClass)){
  //if(charClass==NULL){
    printk(KERN_ALERT "can not make class for the device %s",DEVICE_NAME);
    unregister_chrdev(Major, DEVICE_NAME);
    return -1;
  }
  printk(KERN_ALERT "Device Class Created!\n");

```
and we register the device with the name "hooker_dev":
```c
 if(device_create(charClass, NULL, MKDEV(Major, 0), NULL, DEVICE_NAME)==NULL){
    class_destroy(charClass);
    unregister_chrdev(Major, DEVICE_NAME);
    printk(KERN_ALERT "can not make node for device %s",DEVICE_NAME);
    return -1;
  }

  printk(KERN_INFO "%s:I was assigned major number %d\n", name,Major);
  ```
  **NOTE:** above steps is necessery as we want to get config file from user!
  and finally we register net hook:
  ```sh
  ret = nf_register_net_hook(&init_net,&packet_drop); // Record in net filtering
  if(ret)
      printk(KERN_INFO "FAILED");
  mutex_init(&char_mutex); 
  
  return  ret;
  ```
  
  #exit function

```c
 device_destroy(charClass, MKDEV(Major, 0));           // remove the device
  class_unregister(charClass);                          // unregister the device class
  class_destroy(charClass);                             // remove the device class
  unregister_chrdev(Major, DEVICE_NAME);
  nf_unregister_net_hook(&init_net,&packet_drop);
  printk(KERN_INFO"%s:Goodby OS class\n",name);
  mutex_destroy(&char_mutex); 
```
It is obvious we do reverse of init !!
we destroy the device/ unregister and destroy class 
release gotten Major number
and at last we destroy the mutex! (will be discussed next)

# open function
```c
if(!mutex_trylock(&char_mutex)){
      printk(KERN_ALERT "%s: Device in use by another process",name);
      return -EBUSY;
    }
    Device_Open++;
    printk(KERN_INFO"%s:device %s is opened\n", DEVICE_NAME,name);
    return 0;
```
above code checks if only one app is opening the kernel device!
after making sure we increse Device_Open and log success message!

# release function
```c
 Device_Open--;
  mutex_unlock(&char_mutex); 
  printk(KERN_INFO"%s:device %s is closed\n", name,DEVICE_NAME);
  return 0;
  ```
  decrease Device_Open and unlock mutex so its availabe for another program (or this program's future executation!) to open kernel device.
  
  #self atoi function
  ```sh
u16 atoi(char * s)
{
  u16 res=0;
  u16 i=0;
  while(s[i])
  {
    res*=10;
    res+=s[i++]-'0';
  }
  return res;
}
```
I have written this function for converting string into number

#write function
here we parse the configuration and apply changes!
we use copy_from_user function because we are moving from user space to kernel space!
we get first byte it is either '0' or '1'
we interpret '0' as block list and '1'  as white list and copy it into allow variable.
```c
for(i=2;kernel_buffer[i]!='\n';i++)
  {
    if(kernel_buffer[i]=='#')
      numOfFilter++;
  }
  ```
  we get number of records by counting # made by user program
  **Note:** we could directly pass the numOfFilter variable with help of my own atoi function[j*ust like network ports in configure file*] but we did this just as a fun!!
  
  and we do some messy string parsing:
  ```c
  offset=i+1;
  for(l=0;l<numOfFilter;l++)
  {
    for(i=0;kernel_buffer[i+offset]!=':';i++)
    {
      
        ips[l][i]=kernel_buffer[i+offset];
    }
    ips[l][i]=0;
    offset+=i+1;
    for(i=0;kernel_buffer[i+offset]!='\n';i++)
    {
        tempPine[i]=kernel_buffer[i+offset];
    }
    tempPine[i]=0;
    ports[l]=atoi(tempPine);
    offset+=i+1;
  }
  ```
  this code will  read an ip and a port and jump to next one it will write in to arrays ips and ports till the index numOfFilter-1
  after this we log the config records!!
  ```c
  printk(KERN_INFO "%s:status : %d\n",name,allow);
  for (i=0;i<numOfFilter;i++)
  {
      printk(KERN_INFO "%s:%d\n",ips[i],ports[i]);
  }
  return len;
  ```
# equlAddresses function
this function is written only to compare to (ip,port) .
**Note: **this could be done with string "ip:port" but i taught this way looks better!
```c
 u16 i;
  
  if(port1!=port2)
    return 0;
  for(i=0;ip1[i];i++)
  {
      if(ip1[i]!=ip2[i])
        return 0;
  }
  if(ip2[i]!=0)
    return 0;
  else
  {
    printk(KERN_INFO "address matched!!\n");
    return 1;
  }
```
it will return true only if both ips and ports are exactly the same!

 #init and exit joint
 ```c
 module_init(lkm_example_init);
 module_exit(lkm_example_exit);
```
this two lines will link our function to kernel init and exit.
#final hooker function
this is hart of the project it will decide to accept or drop packet!
lets go and see how!

```c
        struct timeval curr_tm;
        u16 i;
        sock_buff = skb;
        if(!sock_buff)  return NF_DROP;
        portNum=0;
        ip_header=ip_hdr(skb);
        sprintf(ip_address,"%pI4",&ip_header->saddr);
        udph=udp_hdr(skb);
        portNum=ntohs(udph->source);
        if(ip_header->protocol !=IPPROTO_UDP && ip_header->protocol !=IPPROTO_TCP)
          return NF_ACCEPT;
```
when any new packets arrives in system this function is called if it's empty we drop it else we get ip and port from it's header.
we did this with udp header function because it is consistent with tcp too!
- 1. ntohs function is used due to different platform and architecture concept of bitts(little endian big endian)

```c
do_gettimeofday(&curr_tm);
          printk("logPacket:TIME: %.2lu:%.2lu:%.2lu>received address=%s:%d\n",(curr_tm.tv_sec / 3600+3) % (24),
          (curr_tm.tv_sec / 60+30) % (60),
           curr_tm.tv_sec % 60,
          ip_address,portNum);
```
we get the current time and log it with logPacket tag.

now we have three possible values for allow variable:
 -  2:
 	firewall is turned off so we accept any packet!!

- 1:
	white list mode is selected so we accpet packet only of its source ip and port matches one of our white list else we drop!
	```c
	for(i=0;i<numOfFilter;i++)
            {
              if(equlAddresses(ips[i],ports[i],ip_address,portNum))
              {
                return NF_ACCEPT;
              }
            }
            return NF_DROP;
```
-  0:
	black list mode is selected so we accpet packets except see one packet with source address mathes our black list!
	```c
	for(i=0;i<numOfFilter;i++)
          {
            if(equlAddresses(ips[i],ports[i],ip_address,portNum))
              return NF_DROP;
          }
          return NF_ACCEPT;
```
if allow had any other value we turn firewall off!

thats it :)


### make
It is done with:
```sh
$ make
```
just this!!

For loading the kernel enter:
```sh
$ sudo insmod myModule.ko
```
Note : In some newer version of kernel you can not use kernel without signiture by default So you can use:
```sh
$ sudo insmod -f myModule.ko
```
you can remove it by
```sh
$ sudo rmmod myModule.ko
```
you can check if every thing goes fine by
```sh
$ journalctl -f
```
you must see hello message log!

### appwiter

This is example of loading config into kernel module!

```sh
$ ./app_writer conf
```
conf file content:
>whitelist
192.168.43.200:80
192.168.43.1:8888
192.168.43.1:80

now only these listed adresses are allowed as source!!

