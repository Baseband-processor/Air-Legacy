// Made by Edoardo Mantovani, 2020

// control cfg80211 eco-system
#ifdef __NET_CFG80211_H

#include "config.h"

#ifndef __CFG80211_CONFIG__
#define __CFG80211_CONFIG__

#define USE_DRV_CFG80211		1

int cfg80211_init(lorcon_t *);
int tx80211_cfg80211_capabilities();
lorcon_driver_t *drv_cfg80211_listdriver(lorcon_driver_t *);
void convert_key_from_CPU(struct brcmf_wsec_key *key, struct brcmf_wsec_key_le *key_length);
#endif
#endif
