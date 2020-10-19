// Made by Edoardo Mantovani, 2020
// this file is still under development, probably will be converted into XS for perl library

#include "cfg80211_control.h"
#include "dhd.h"
#include <stdint.h>
#include <linux/types.h>
#include <asm/byteorder.h>

// NOTE: types.h contains __le32 and other types, suggested static linking

// NOTE2: byteorder.h contains the definitions for cpu_to_le-X- functions

#define WLAN_MAX_KEY_LEN 32
#define ETH_ALEN 6

struct brcmf_wsec_key {
	u32 index;		
	u32 len;		
	u8 data[WLAN_MAX_KEY_LEN];	
	u32 pad_1[18];
	u32 algo;	
	u32 flags;	
	u32 pad_2[3];
	u32 iv_initialized;	
	u32 pad_3;
	struct {
		u32 hi;	
		u16 lo;	
	} rxiv;
	u32 pad_4[2];
	u8 ea[ETH_ALEN];	
};

struct brcmf_wsec_key_le {
	__le32 index;		
	__le32 len;		
	u8 data[WLAN_MAX_KEY_LEN];	
	__le32 pad_1[18];
	__le32 algo;	
	__le32 flags;	
	__le32 pad_2[3];
	__le32 iv_initialized;	
	__le32 pad_3;
	struct {
		__le32 hi;	
		__le16 lo;	
	} rxiv;
	__le32 pad_4[2];
	u8 ea[ETH_ALEN];	
};


void convert_key_from_CPU(struct brcmf_wsec_key *key, struct brcmf_wsec_key_le *key_length){
	key_length->index = cpu_to_le32(key->index);
	key_length->len = cpu_to_le32(key->len);
	key_length->algo = cpu_to_le32(key->algo);
	key_length->flags = cpu_to_le32(key->flags);
	key_length->rxiv.hi = cpu_to_le32(key->rxiv.hi);
	key_length->rxiv.lo = cpu_to_le16(key->rxiv.lo);
	key_length->iv_initialized = cpu_to_le32(key->iv_initialized);
	memcpy(key_length->data, key->data, sizeof(key->data));
	memcpy(key_length->ea, key->ea, sizeof(key->ea));
}

int send_key_to_dongle(struct brcmf_if *ifp, struct brcmf_wsec_key *key){
	struct brcmf_pub *drvr = ifp->drvr;
	int err;
	struct brcmf_wsec_key_le key_le;

	convert_key_from_CPU(key, &key_le); // DONE

	brcmf_netdev_wait_pend8021x(ifp);

	err = brcmf_fil_bsscfg_data_set(ifp, "wsec_key", &key_le, sizeof(key_le));

	if (err){
		printf("wsec_key error (%d)\n", err);
		}
	return err;
}
