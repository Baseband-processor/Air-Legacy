// Made by Edoardo Mantovani, 2020
// this file is still under development, probably will be converted into XS for perl library

#include "cfg80211_control.h"
#include "dhd.h"
#include <stdint.h>
#include <linux/types.h>
#include <asm/byteorder.h>
#include <linux/netdevice.h>
#include <linux/sched.h>
#include <linux/mutex.h>

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


typedef struct { int counter; } atomic_t;
#define atomic_read(v)		((v)->counter)

int brcmf_get_pend_8021x_cnt(struct brcmf_pub *drvr){
	return atomic_read(&drvr->pend_8021x_cnt);
}

#define MAX_WAIT_FOR_8021X_TX	10
#define TASK_INTERRUPTIBLE 1
#define TASK_RUNNING 0
#define EIO 5 
#define HZ 1000

u32 brcmf_create_iovar(char *name, const char *data, u32 datalen,char *buf, u32 buflen){
	u32 len;
	len = strlen(name) + 1;
	if ((len + datalen) > buflen){
		return 0;
	}
	memcpy(buf, name, len);

	if (data && datalen){
		memcpy(&buf[len], data, datalen);
	}
	return len + datalen;
}

int brcmf_netdev_wait_pend8021x(struct net_device *ndev){
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_pub *drvr = ifp->drvr;
	int timeout = 10 * HZ / 1000;
	int ntimes = MAX_WAIT_FOR_8021X_TX;
	int pend = brcmf_get_pend_8021x_cnt(drvr);

	while (ntimes && pend) {
		if (pend) {
			set_current_state(TASK_INTERRUPTIBLE); // set_current_state() changes the state of the currently executing process from TASK_RUNNING to TASK_INTERRUPTIBLE.
			schedule_timeout(timeout);
			set_current_state(TASK_RUNNING);
			ntimes--;
		}
		pend = brcmf_get_pend_8021x_cnt(drvr);
	}
	return pend;
}

u32
brcmf_create_bsscfg(s32 bssidx, char *name, char *data, u32 datalen, char *buf, u32 buflen) {
	const s8 *prefix = "bsscfg:";
	s8 *p;
	u32 prefixlen;
	u32 namelen;
	u32 iolen;
	__le32 bssidx_le;

	if (bssidx == 0){
		return brcmf_create_iovar(name, data, datalen, buf, buflen);
	}
	prefixlen = strlen(prefix);
	namelen = strlen(name) + 1; /* lengh of iovar  name + null */
	iolen = prefixlen + namelen + sizeof(bssidx_le) + datalen;

	if (buflen < iolen) {
		brcmf_err("buffer is too short\n");
		return 0;
	}

	p = buf;
	memcpy(p, prefix, prefixlen);
	p += prefixlen;
	memcpy(p, name, namelen);
	p += namelen;
	bssidx_le = cpu_to_le32(bssidx);
	memcpy(p, &bssidx_le, sizeof(bssidx_le));
	p += sizeof(bssidx_le);
	if (datalen){
		memcpy(p, data, datalen);
	}
	return iolen;
}

int brcmf_proto_query_dcmd(struct brcmf_pub *drvr, int ifidx, uint cmd, void *buf, uint len){
    return drvr->proto->query_dcmd(drvr, ifidx, cmd, buf, len);
}

int brcmf_proto_set_dcmd(struct brcmf_pub *drvr, int ifidx, uint cmd, void *buf, uint len){
     return ( drvr->proto->set_dcmd(drvr, ifidx, cmd, buf, len) );
 }

s32
brcmf_fil_cmd_data(struct brcmf_if *ifp, u32 cmd, void *data, u32 len, bool set){
	struct brcmf_pub *drvr = ifp->drvr;
	s32 err;

	if (drvr->bus_if->state != BRCMF_BUS_UP) {
		printf("bus is down. we have nothing to do.\n");
		return -EIO;
	}

	if (data != NULL)
		len = min_t(uint, len, BRCMF_DCMD_MAXLEN);
	if (set){
		err = brcmf_proto_set_dcmd(drvr, ifp->ifidx, cmd, data, len);
	}else{
		err = brcmf_proto_query_dcmd(drvr, ifp->ifidx, cmd, data, len);
	}
	if (err >= 0){
		return 0;
	}
	//brcmf_dbg(FIL, "Failed: %s (%d)\n", brcmf_fil_get_errstr((u32)(-err)), err);
	return -EBADE;
}

#define EPERM 1
s32 brcmf_fil_bsscfg_data_set(struct brcmf_if *ifp, char *name, void *data, u32 len)
{
	struct brcmf_pub *drvr = ifp->drvr;
	s32 err;
	u32 buflen;

	mutex_lock(&drvr->proto_block);

	brcmf_dbg(FIL, "bssidx=%d, name=%s, len=%d\n", ifp->bssidx, name, len);
	brcmf_dbg_hex_dump(BRCMF_FIL_ON(), data, min_t(uint, len, MAX_HEX_DUMP_LEN), "data");

	buflen = brcmf_create_bsscfg(ifp->bssidx, name, data, len, drvr->proto_buf, sizeof(drvr->proto_buf));
	if (buflen) {
		err = brcmf_fil_cmd_data(ifp, BRCMF_C_SET_VAR, drvr->proto_buf, buflen, true);
	} else {
		err = -EPERM;
		printf("Creating bsscfg failed\n");
	}

	mutex_unlock(&drvr->proto_block);
	return err;
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
