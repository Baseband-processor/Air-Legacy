#include <sys/stat.h> 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

#include <net/if.h>
#include <net/if_tun.h>

#ifdef __UCLIBC__
  extern int init_module(void *module, unsigned long len, const char *options);
#else
# include <sys/syscall.h>
# define init_module(mod, len, opts) syscall(__NR_init_module, mod, len, opts)
#endif

/* check if TUN device exists */
int check_tun() 
{
  struct stat  buffer;   
  return (stat("/dev/net/tun", &buffer) == 0);
}

/* if TUN doesn't exists, create it!*/
// DOCUMENTATION: https://www.kernel.org/doc/Documentation/networking/tuntap.txt
int create_tun(){
  if( check_tun() != -1 ){
      return -1;
  }else{
    mknod("/dev/net/tun". "c", 10, 200);
    // set permissions
    chmod ("/dev/net/tun", '0666');
    //open device
    int fd = open("/dev/net/tun", O_RDWR);
    // load into modprobe
    init_module("tun", sizeof(fd), ""); // same as ' modprobe tun  '
    return 1; // success
  }
}


  
  // define possible flags
  
  #define IFF_TUN                0x0001
  #define IFF_TAP                0x0002
  #define IFF_NO_PI              0x1000
  #define IFF_ONE_QUEUE          0x2000
  #define IFF_VNET_HDR           0x4000
  #define IFF_TUN_EXCL           0x8000

  char *tuntap_dev = "/dev/net/tun";
  
  char * initialize_tun(int flags)
  {
  struct ifreq ifr; 
  //open device
  int fd = open(tuntap_dev, O_RDWR);

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = flags;   

  ioctl(fd, TUNSETIFF, (void *) &ifr)); // send TUNSETIFF ioctl

  strcpy(dev, ifr.ifr_name);

}

  }

