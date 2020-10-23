// Made by Edoardo Mantovani, 2020

// control cfg80211 eco-system
#ifdef __NET_CFG80211_H

#include "config.h"

#ifndef __CFG80211_CONFIG__
#define __CFG80211_CONFIG__

#define USE_DRV_CFG80211		1

int cfg80211_init(lorcon_t *);
lorcon_driver_t *drv_cfg80211_listdriver(lorcon_driver_t *);
void convert_key_from_CPU(struct brcmf_wsec_key *key, struct brcmf_wsec_key_le *key_length);
int send_key_to_dongle(struct brcmf_if *ifp, struct brcmf_wsec_key *key);
int brcmf_cfg80211_request_ap_if(struct brcmf_if *ifp);
wireless_dev_t *brcmf_mon_add_vif(struct wiphy *wiphy, const char *name); // typedef struct wireless_dev wireless_dev_t
wireless_dev_t *brcmf_cfg80211_add_iface(struct wiphy *wiphy, const char *name, unsigned char name_assign_type, enum nl80211_iftype type, struct vif_params *params);
s32 brcmf_notify_escan_complete(struct brcmf_cfg80211_info *cfg, struct brcmf_if *ifp, bool aborted, bool fw_abort); // signed integer
#endif
#endif
