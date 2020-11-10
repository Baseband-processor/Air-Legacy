#ifndef __PROGRAM_DRI_H
#define __PROGRAM_DRI_H

#define SSID_DUMMY 32
#include "cfg80211.h"

//examples taken from https://www.apriorit.com/dev-blog/645-lin-linux-wi-fi-driver-tutorial-how-to-write-simple-linux-wireless-driver-prototype

struct driver_context {
  struct wiphy *wiphy;
  struct net_device *netdev;
  struct semaphore sem;
  struct work_struct ws_connect;
  char connecting_ssid[sizeof(SSID_DUMMY)];
  struct work_struct ws_disconnect;
  u16 disconnect_reason_code;
  struct work_struct ws_scan;
  struct cfg80211_scan_request *scan_request;
}; 


struct driver_ndev_priv_context {
  struct driver_context *dri;
  struct wireless_dev wdev;
};  

static int __init virtual_wifi_init();
static void __exit virtual_wifi_exit();
static struct driver_context *driver_create_context();

#endif
