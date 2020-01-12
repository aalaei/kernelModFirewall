#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
//#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include<linux/time.h>

static DEFINE_MUTEX(char_mutex); 
static DEFINE_MUTEX(flag_mutex); 

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ali alaei");
MODULE_DESCRIPTION("A simple network Linux module.");
MODULE_VERSION("1.00");

static char * name ="fireWall";
module_param(name, charp, S_IRUGO); ///< Param desc. charp = char ptr, S_IRUGO can be read/not changed
MODULE_PARM_DESC(name, "The name to display in /var/log/kern.log");  ///< parameter description

#define DEVICE_NAME "hooker_dev"
#define CLASS_NAME "hooker_class"
#define BUF_LEN  256

static int Major;
static int Device_Open = 0;
static char kernel_buffer[BUF_LEN];

static int buff_len = 0;
static struct class*  charClass;

static int device_open(struct inode *inode, struct file *filp);
static int device_release(struct inode *inode, struct file *filp);
static ssize_t device_write(struct file *filp, const char *buf, size_t len, loff_t *off);
static ssize_t device_read(struct file *filp, char *buffer, size_t length,  loff_t *offset);

static struct file_operations fops = {
  .write = device_write,
  .open = device_open,
  .release = device_release,
  .read = device_read,
};

struct sk_buff *sock_buff; //socket buffer
struct iphdr *ip_header; // ip header
struct udphdr *udph; // udp header
//struct tcphdr *tcph; //tcp header
char ip_address[16]; // ip address
u16 portNum;  //port number
int flag=0;
int allow=2; // 0>black list /1>white list
char ips[100][16]; // ips which we are intrested in!
u16 ports[100];  //ports  which we are intrested in!
int numOfFilter=0; // number of records in config file!



unsigned int hooker(unsigned int hooknum, struct sk_buff *skb,
                       const struct net_device *in, const struct net_device *out,
                       int(*okfn)(struct sk_buff *));


static struct nf_hook_ops packet_drop __read_mostly = {
        .pf = NFPROTO_IPV4,
        .priority = NF_IP_PRI_FIRST,
        .hooknum =NF_INET_LOCAL_IN,
        .hook = (nf_hookfn *) hooker
};

//this method is invoked when insmod the module
static int __init lkm_example_init(void) {
  int ret;
  printk(KERN_INFO "Hello %s\n",name);

  Major = register_chrdev(0, DEVICE_NAME, &fops);

  if (Major < 0) {
    printk(KERN_ALERT "Registering char device failed with %d\n", Major);
    return Major;
  }
  printk(KERN_ALERT "Char device Registerd with  %d\n", Major);


  charClass = class_create(THIS_MODULE, CLASS_NAME);
  if(IS_ERR(charClass)){
  //if(charClass==NULL){
    printk(KERN_ALERT "can not make class for the device %s",DEVICE_NAME);
    unregister_chrdev(Major, DEVICE_NAME);
    return -1;
  }
  printk(KERN_ALERT "Device Class Created!\n");

  if(device_create(charClass, NULL, MKDEV(Major, 0), NULL, DEVICE_NAME)==NULL){
    class_destroy(charClass);
    unregister_chrdev(Major, DEVICE_NAME);
    printk(KERN_ALERT "can not make node for device %s",DEVICE_NAME);
    return -1;
  }

  printk(KERN_INFO "%s:I was assigned major number %d\n", name,Major);
 //return 0;
  
  ret = nf_register_net_hook(&init_net,&packet_drop); // Record in net filtering
  if(ret)
      printk(KERN_INFO "FAILED");
  mutex_init(&char_mutex); 
  mutex_init(&flag_mutex);

  return  ret;
}

//this method is invoked when rmmod the module
static void __exit lkm_example_exit(void){
  device_destroy(charClass, MKDEV(Major, 0));           // remove the device
  class_unregister(charClass);                          // unregister the device class
  class_destroy(charClass);                             // remove the device class
  unregister_chrdev(Major, DEVICE_NAME);
  nf_unregister_net_hook(&init_net,&packet_drop);
  printk(KERN_INFO"%s:Goodby OS class\n",name);
  mutex_destroy(&char_mutex); 
  mutex_destroy(&flag_mutex);
}

//this method is invoked when the device file is opened in the application
static int device_open(struct inode *inode, struct file *filp)
  {
    /*
    if(!mutex_trylock(&char_mutex)){
      printk(KERN_ALERT "%s: Device in use by another process",name);
      return -EBUSY;
    }
    */

    Device_Open++;
    printk(KERN_INFO"%s:device %s is opened\n", DEVICE_NAME,name);
    return 0;
  }


//this method is invoked when the device file is closed in the application
static int device_release(struct inode *inode, struct file *filp)
{
  Device_Open--;
  //mutex_unlock(&char_mutex); 
  printk(KERN_INFO"%s:device %s is closed\n", name,DEVICE_NAME);
  return 0;
}

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

//this method is invoked when writing to the device in application
static ssize_t device_write(struct file *filp, const char *user_buffer, size_t len, loff_t *off)
{
  char tempPine[50];
  u32 i,offset,l;
  //mutex_lock(&conf_mutex);
  printk(KERN_ALERT "%s:Writing to the device %s.\n",name, DEVICE_NAME);
  //
  mutex_lock(&char_mutex); 
  copy_from_user(kernel_buffer, user_buffer,len);
  buff_len = len;
  //printk(KERN_INFO "config file:\n%s\n",kernel_buffer);
  numOfFilter=0;  
  if(kernel_buffer[0]=='1')
    allow=1;
  else if(kernel_buffer[0]=='0')
    allow=0;
  else
  {
    printk(KERN_ALERT "%s:Error config syntax!!\n",name);
    allow=2;
    return buff_len;
  }
  mutex_unlock(&char_mutex); 
  // now we know type of file!
  if(allow==1)
  {
    while(flag); // to fifo white list after black list!!
    //or to ignore white lists meanwhile black list:
    //return len;
  }else{
    mutex_lock(&flag_mutex); 
    flag=1;
    mutex_unlock(&flag_mutex); 
  }

  mutex_lock(&char_mutex); 
  if(allow==0)
    {
      mutex_lock(&flag_mutex); 
      flag=0;
      mutex_unlock(&flag_mutex); 
    }
  
  for(i=2;kernel_buffer[i]!='\n';i++)
  {
    if(kernel_buffer[i]=='#')
      numOfFilter++;
  }
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
  }//end of critical section
  mutex_unlock(&char_mutex); 
  printk(KERN_INFO "%s:status : %d\n",name,allow);
  for (i=0;i<numOfFilter;i++)
  {
      printk(KERN_INFO "%s:%d\n",ips[i],ports[i]);
  }
  return len;
}
static ssize_t device_read(struct file *filp, /* see include/linux/fs.h   */
                           char *user_buffer,      /* buffer to fill with data */
                           size_t length,     /* length of the buffer     */
                           loff_t *offset)
{
  printk(KERN_ALERT "Reading from the device %s.\n", DEVICE_NAME);

  if (length<=buff_len){
    copy_to_user(user_buffer, kernel_buffer, length);
    return length;
  }else{
    copy_to_user(user_buffer, kernel_buffer, buff_len);
    return buff_len;
  }

 }

u8 equlAddresses(char * ip1,u16 port1,char * ip2,u16 port2)
{
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
}
unsigned int hooker(unsigned int hooknum, struct sk_buff *skb,

        const struct net_device *in, const struct net_device *out,

        int(*okfn)(struct sk_buff *))

{
        struct timeval curr_tm;
        u16 i;
        sock_buff = skb;
        //ip_header = (struct iphdr *)skb_network_header(sock_buff);
        if(!sock_buff)  return NF_DROP;
        portNum=0;
        ip_header=ip_hdr(skb);

        sprintf(ip_address,"%pI4",&ip_header->saddr);
        udph=udp_hdr(skb);
        portNum=ntohs(udph->source);
        
        if(ip_header->protocol !=IPPROTO_UDP && ip_header->protocol !=IPPROTO_TCP)
          return NF_ACCEPT;
        /* no needed
        if (ip_header->protocol == IPPROTO_UDP) {
          udph=udp_hdr(skb);
          portNum=ntohs(udph->source);
        }else if (ip_header->protocol == IPPROTO_TCP) {
          tcph=tcp_hdr(skb);
          //portNum=ntohs(tcph->source);
          udph=udp_hdr(skb);
          portNum=ntohs(udph->source);

        }
        */
          do_gettimeofday(&curr_tm);
          printk("logPacket:TIME: %.2lu:%.2lu:%.2lu>received address=%s:%d\n",(curr_tm.tv_sec / 3600+3) % (24),
          (curr_tm.tv_sec / 60+30) % (60),
           curr_tm.tv_sec % 60,
          ip_address,portNum);
        if(allow==2)
          return NF_ACCEPT;
        else if(allow==1)
        {
          for(i=0;i<numOfFilter;i++)
          {
            if(equlAddresses(ips[i],ports[i],ip_address,portNum))
              return NF_ACCEPT;
          }
          return NF_DROP;
          
        }else if (allow==0)
        {
            for(i=0;i<numOfFilter;i++)
            {
              if(equlAddresses(ips[i],ports[i],ip_address,portNum))
              {
                return NF_DROP;
              }
            }
            return NF_ACCEPT;
        }else
        {
          return NF_ACCEPT;
        }

}

module_init(lkm_example_init);
module_exit(lkm_example_exit);
