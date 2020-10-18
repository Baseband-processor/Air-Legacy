// Made by Edoardo Mantovani, 2020

// control cfg80211 eco-system

#include "config.h"

#ifndef __CFG80211_CONFIG__
#define __CFG80211_CONFIG__

#define USE_DRV_CFG80211		1

int cfg80211_init(lorcon_t *);
int tx80211_cfg80211_capabilities();
lorcon_driver_t *drv_cfg80211_listdriver(lorcon_driver_t *);

#endif
