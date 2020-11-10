#include <sys/stat.h> 

int check_tun() 
{
  struct stat  buffer;   
  return (stat("/dev/net/tun", &buffer) == 0);
}

#ifndef _UAPI__IF_TUN_H || check_tun()

#else
  #include <stdio.h>
  #include <stdlib.h>
  #include <string.h>
  
  #include <net/if.h>
  #include <net/if_tun.h>
  
  // define possible flags
  
  #define IFF_TUN                0x0001
  #define IFF_TAP                0x0002
  #define IFF_NO_PI              0x1000
  #define IFF_ONE_QUEUE        0x2000
  #define IFF_VNET_HDR        0x4000
  #define IFF_TUN_EXCL        0x8000

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
#endif
