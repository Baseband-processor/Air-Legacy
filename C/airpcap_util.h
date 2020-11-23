#include <net/if_arp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

//m#include <linux/types.h>
#include <net/if.h>

#include "airpcap.h"

void setebuf(PCHAR ebuf, const char *format, ...);

int ifconfig_set_flags(const char *in_dev, short flags);
int ifconfig_get_flags(const char *in_dev, short *flags);
int ifconfig_ifupdown(const char *in_dev, int devup);
int ifconfig_get_hwaddr(const char *dev, uint8_t *hwaddr);
