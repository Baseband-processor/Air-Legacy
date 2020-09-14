/*
    This file is part of lorcon
    lorcon is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
    lorcon is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with lorcon; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
    Copyright (c) 2005 dragorn and Joshua Wright
*/

#ifndef __TX80211_H__
#define __TX80211_H__

#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "tx80211_packet.h"
#include "tx80211_errno.h"

/* Error string length */
#define TX80211_STATUS_MAX		1024

#define MAX_IFNAME_LEN			32

/* Get the version */
unsigned int tx80211_getversion();

/* Master tx80211 interface structure */
struct tx80211 {
	/* 
	 * Internal functions and structs 
	 *
	 * These should not be called directly.
	 */

	int injectortype;
	char ifname[MAX_IFNAME_LEN];
	uint32_t capabilities;
	int raw_fd;
	int ioctl_fd;
	int packets_sent;
	int packets_recv;

	int dlt;

	int mode;
	int channel;
	int rate;

	/* Error buffer */
	char errstr[TX80211_STATUS_MAX];

	/* Record the starting MAC address to restore if changed */
	uint8_t startingmacset;
	uint8_t startingmac[6];

	/* Extra space for use by the driver code */
	void *extra;

	/* Callthroughs to functions installed by the setup when the injector is
	 * defined. */
	int (*open_callthrough) (struct tx80211 *);
	int (*close_callthrough) (struct tx80211 *);

	int (*setmode_callthrough) (struct tx80211 *, int);
	int (*getmode_callthrough) (struct tx80211 *);

	int (*setfuncmode_callthrough) (struct tx80211 *, int);

	int (*setchan_callthrough) (struct tx80211 *, int);
	int (*getchan_callthrough) (struct tx80211 *);

	int (*txpacket_callthrough) (struct tx80211 *, struct tx80211_packet *);

	int (*selfack_callthrough) (struct tx80211 *, uint8_t *);
};
typedef struct tx80211 tx80211_t;

/* Dynamic structure of supported cards, for clients to list supported types */
struct tx80211_cardlist {
	char **cardnames;
	char **descriptions;
	int *capabilities;
	int num_cards;
	int *injnum;
};
typedef struct tx80211_cardlist tx80211_cardlist_t;

/* Breakout structure of decoded information */
struct tx80211_decode {
	/* bitmap to preserve integrity between lib binaries.  Flags indicate content of
	 * structure, NOT availability of data in each field. */
	uint32_t decode_bitmap;

	/* dot11 basic decode */
	int pkt_length;
	uint8_t *pkt_head;
	uint8_t *pkt_dot11;
	uint8_t *pkt_data;
};
typedef struct tx80211_decode tx80211_decode_t;

#define TX80211_DECODE_NONE			0
#define TX80211_DECODE_DOT11BASIC	1
#define TX80211_DECODE_RESERVED		31
#define TX80211_DECODE_FLAGSET		(TX80211_DECODE_DOT11BASIC)

enum tx80211_radiotap_type {
	TX_IEEE80211_RADIOTAP_TSFT = 0,
	TX_IEEE80211_RADIOTAP_FLAGS = 1,
	TX_IEEE80211_RADIOTAP_RATE = 2,
	TX_IEEE80211_RADIOTAP_CHANNEL = 3,
	TX_IEEE80211_RADIOTAP_FHSS = 4,
	TX_IEEE80211_RADIOTAP_DBM_ANTSIGNAL = 5,
	TX_IEEE80211_RADIOTAP_DBM_ANTNOISE = 6,
	TX_IEEE80211_RADIOTAP_LOCK_QUALITY = 7,
	TX_IEEE80211_RADIOTAP_TX_ATTENUATION = 8,
	TX_IEEE80211_RADIOTAP_DB_TX_ATTENUATION = 9,
	TX_IEEE80211_RADIOTAP_DBM_TX_POWER = 10,
	TX_IEEE80211_RADIOTAP_ANTENNA = 11,
	TX_IEEE80211_RADIOTAP_DB_ANTSIGNAL = 12,
	TX_IEEE80211_RADIOTAP_DB_ANTNOISE = 13,
	TX_IEEE80211_RADIOTAP_FCS = 14,
	TX_IEEE80211_RADIOTAP_EXT = 31,
};

/*
 * Defines the value in the radiotap it_present field for supplied data
 * bitmasks.
 */

#ifdef _MSC_VER
#pragma pack(push, 1)
#endif

struct tx80211_radiotap_header {
	uint8_t it_version;		/* Version 0. Only increases
					 * for drastic changes,
					 * introduction of compatible
					 * new fields does not count.
					 */
	uint8_t it_pad;
	uint16_t it_len;		/* length of the whole
					 * header in bytes, including
					 * it_version, it_pad,
					 * it_len, and data fields.
					 */
	uint32_t it_present;		/* A bitmap telling which
					 * fields are present. Set bit 31
					 * (0x80000000) to extend the
					 * bitmap by another 32 bits.
					 * Additional extensions are made
					 * by setting bit 31.
					 */
	uint8_t wr_flags;		/* Flags, not used by LORCON, but
					 * included for word boundary padding.
					 */
    uint8_t wr_rate;		/* Data rate in 500 Kbps increments */
	uint16_t wr_chan_freq;		/* Frequency flags */
	uint16_t wr_chan_flags;		/* Modulation flags */
}
#ifdef _MSC_VER
#pragma pack(pop)
#else		
__attribute__((__packed__))
#endif
;

#define TX80211_RTAP_PRESENT (1 << TX_IEEE80211_RADIOTAP_FLAGS | \
			      1 << TX_IEEE80211_RADIOTAP_RATE  | \
			      1 << TX_IEEE80211_RADIOTAP_CHANNEL)
#define TX80211_RTAP_LEN sizeof(struct tx80211_radiotap_header)

/* Functional modes (you should probably be using these to set the mode
 * instead of calling SetMode() directly.  These modes can be combined
 * if the card supports them, and the actual modes set will be.  It's
 * possible that one mode will be able to perform other tasks (ie, some cards
 * may support inject in monitor mode w/ no special tricks) but it's a wise
 * idea to use the proper mode, INJMON, for that) */
#define TX80211_FUNCMODE_RFMON		0
#define TX80211_FUNCMODE_INJECT		1
#define TX80211_FUNCMODE_INJMON		2

/* Modes for setting various operation types.  This aligns with the standard
 * Linux wireless operation modes, but doesn't tie us to the IW literals. */
#define TX80211_MODE_AUTO	0   /* Let the driver decides */
#define TX80211_MODE_ADHOC	1   /* Single cell network */
#define TX80211_MODE_INFRA	2   /* Multi cell network, roaming, ... */
#define TX80211_MODE_MASTER	3   /* Synchronisation master or Access Point */
#define TX80211_MODE_REPEAT	4   /* Wireless Repeater (forwarder) */
#define TX80211_MODE_SECOND	5   /* Secondary master/repeater (backup) */
#define TX80211_MODE_MONITOR	6   /* Passive monitor (listen only) */

/* tx80211 device capabilities */
#define TX80211_CAP_NONE	0	/* no capabilities */
#define TX80211_CAP_SNIFF	1	/* capable of standard rfmon sniffing */
#define TX80211_CAP_TRANSMIT	2	/* capable of basic transmitting */
#define TX80211_CAP_SEQ		4	/* capable of sequence spoofing */
#define TX80211_CAP_BSSTIME	8	/* capable of bss timestamp spoofing */
/* CAP_PHY deprecated */
/* #define TX80211_CAP_PHY		16 */
#define TX80211_CAP_FRAG	32	/* capable of sending fragments */
#define TX80211_CAP_CTRL	64	/* capable of sending ctrl frames */
#define TX80211_CAP_DURID	128	/* Capable of setting DUR/ID field */
#define TX80211_CAP_SNIFFACK	256	/* Capable of sniffing ACK frames */
#define TX80211_CAP_SELFACK	512	/* Capable of self-acking data frames */
#define TX80211_CAP_TXNOWAIT	1024	/* Capable of TX without CCA/DIFS/IFS */
#define TX80211_CAP_DSSSTX	2048	/* TX in DSSS mode */
#define TX80211_CAP_OFDMTX	4096	/* TX in ODFM mode */
#define TX80211_CAP_MIMOTX	8192	/* TX in MIMO mode, future */
#define TX80211_CAP_SETRATE	16384	/* Capability to set TX data rate */
#define TX80211_CAP_SETMODULATION	32768	/* Capability to set modulation type */

/* 
 * tx802.11 functions for creating and operating on the tx80211 struct 
 * core API of library
 */

/* Injector types */
#define INJ_NODRIVER    0
#define INJ_WLANNG  	1
#define INJ_HOSTAP  	2
#define INJ_AIRJACK 	3
#define INJ_PRISM54 	4
#define INJ_MADWIFIOLD 	5
#define INJ_MADWIFING  	6
#define INJ_RTL8180     7
#define INJ_RT2500		8
#define INJ_RT2570		9
#define INJ_RT73		10
#define INJ_AIRPCAP		11
#define INJ_RT61		12
#define INJ_ZD1211RW	13
#define INJ_BCM43XX     14
#define INJ_MAC80211	15
/*
* No-one should test for INJ_MAX, test for INJ_NODRIVER instead
*/
#define INJ_MAX         16

/* Generic endian flopping macros */
#ifdef WORDS_BIGENDIAN

#define tx80211_hton16(x) (x)
#define tx80211_ntoh16(x) (x)
#define tx80211_be16(x)	  (x)
#define tx80211_le16(x)	  tx80211_swap16((x))

#define tx80211_hton32(x) (x)
#define tx80211_ntoh32(x) (x)
#define tx80211_be32(x)	  (x)
#define tx80211_le32(x)	  tx80211_swap32((x))

#define tx80211_hton64(x) (x)
#define tx80211_ntoh64(x) (x)
#define tx80211_be64(x)	  (x)
#define tx80211_le64(x)	  tx80211_swap64((x))

#else

#define tx80211_hton16(x) tx80211_swap16((x))
#define tx80211_ntoh16(x) tx80211_swap16((x))
#define tx80211_le16(x)	  (x)
#define tx80211_be16(x)	  tx80211_swap16((x))

#define tx80211_hton32(x) tx80211_swap32((x))
#define tx80211_ntoh32(x) tx80211_swap32((x))
#define tx80211_le32(x)	  (x)
#define tx80211_be32(x)	  tx80211_swap32((x))

#define tx80211_hton64(x) tx80211_swap64((x))
#define tx80211_ntoh64(x) tx80211_swap64((x))
#define tx80211_le64(x)	  (x)
#define tx80211_be64(x)	  tx80211_swap64((x))

#endif

/* Swap magic */
#ifdef _MSC_VER

#define tx80211_swap16(x) (uint16_t)( \
		(((uint16_t)(x) & 0x00ff) << 8) | (((uint16_t)(x) & 0xff00) >> 8))

#define tx80211_swap32(x) (uint32_t)( \
        (((uint32_t)(x) & (uint32_t)0x000000ff) << 24) | \
        (((uint32_t)(x) & (uint32_t)0x0000ff00) << 8) | \
        (((uint32_t)(x) & (uint32_t)0x00ff0000) >> 8) | \
        (((uint32_t)(x) & (uint32_t)0xff000000) >> 24) )

#define tx80211_swap64(x) (uint64_t)( \
        (((uint64_t)(x) & (uint64_t)0x00000000000000ffULL) << 56) | \
        (((uint64_t)(x) & (uint64_t)0x000000000000ff00ULL) << 40) | \
        (((uint64_t)(x) & (uint64_t)0x0000000000ff0000ULL) << 24) | \
        (((uint64_t)(x) & (uint64_t)0x00000000ff000000ULL) <<  8) | \
        (((uint64_t)(x) & (uint64_t)0x000000ff00000000ULL) >>  8) | \
        (((uint64_t)(x) & (uint64_t)0x0000ff0000000000ULL) >> 24) | \
        (((uint64_t)(x) & (uint64_t)0x00ff000000000000ULL) >> 40) | \
        (((uint64_t)(x) & (uint64_t)0xff00000000000000ULL) >> 56) )
#else

#define tx80211_swap16(x) \
({ \
    uint16_t __x = (x); \
    ((uint16_t)( \
        (uint16_t)(((uint16_t)(__x) & (uint16_t)0x00ff) << 8) | \
        (uint16_t)(((uint16_t)(__x) & (uint16_t)0xff00) >> 8) )); \
})

#define tx80211_swap32(x) \
({ \
    uint32_t __x = (x); \
    ((uint32_t)( \
        (uint32_t)(((uint32_t)(__x) & (uint32_t)0x000000ff) << 24) | \
        (uint32_t)(((uint32_t)(__x) & (uint32_t)0x0000ff00) << 8) | \
        (uint32_t)(((uint32_t)(__x) & (uint32_t)0x00ff0000) >> 8) | \
        (uint32_t)(((uint32_t)(__x) & (uint32_t)0xff000000) >> 24) )); \
})

#define tx80211_swap64(x) \
({ \
    uint64_t __x = (x); \
    ((uint64_t)( \
        (uint64_t)(((uint64_t)(__x) & (uint64_t)0x00000000000000ffULL) << 56) | \
        (uint64_t)(((uint64_t)(__x) & (uint64_t)0x000000000000ff00ULL) << 40) | \
        (uint64_t)(((uint64_t)(__x) & (uint64_t)0x0000000000ff0000ULL) << 24) | \
        (uint64_t)(((uint64_t)(__x) & (uint64_t)0x00000000ff000000ULL) <<  8) | \
        (uint64_t)(((uint64_t)(__x) & (uint64_t)0x000000ff00000000ULL) >>  8) | \
        (uint64_t)(((uint64_t)(__x) & (uint64_t)0x0000ff0000000000ULL) >> 24) | \
        (uint64_t)(((uint64_t)(__x) & (uint64_t)0x00ff000000000000ULL) >> 40) | \
        (uint64_t)(((uint64_t)(__x) & (uint64_t)0xff00000000000000ULL) >> 56) )); \
})

#endif

/* Byteswap magic for turning an element into the endian format
 * that the driver expects it to be.  These are known to be accurate
 * on little endian systems.  Please confirm with testing on big endian.
 *
 * These are to be used to flip bits when building packet structs.
 */
#ifdef _MSC_VER
static tx80211_endian16(struct tx80211 *x, uint16_t y)
#else
static inline tx80211_endian16(struct tx80211 *x, uint16_t y)
#endif
{
	switch (x->injectortype) {
	case INJ_WLANNG:
	case INJ_HOSTAP:
		return tx80211_be16(y);
	case INJ_PRISM54:
	case INJ_MADWIFIOLD:
		return tx80211_le16(y);
	}
	return y;
}
#ifdef _MSC_VER
static tx80211_endian32(struct tx80211 *x, uint32_t y)
#else
static inline tx80211_endian32(struct tx80211 *x, uint32_t y)
#endif
{
	switch (x->injectortype) {
	case INJ_WLANNG:
	case INJ_HOSTAP:
		return tx80211_be32(y);
	case INJ_PRISM54:
	case INJ_MADWIFIOLD:
		return tx80211_le32(y);
	}
	return y;
}

#ifdef _MSC_VER
static tx80211_endian64(struct tx80211 *x, uint64_t y)
#else
static inline tx80211_endian64(struct tx80211 *x, uint64_t y)
#endif
{
	switch (x->injectortype) {
	case INJ_WLANNG:
	case INJ_HOSTAP:
		return tx80211_be64(y);
	case INJ_PRISM54:
	case INJ_MADWIFIOLD:
		return tx80211_le64(y);
	}
	return y;
}

/* Populate and destroy lists of available tx types 
 * Caller of freecardlist must be aware that in_list is destroyed! */
struct tx80211_cardlist *tx80211_getcardlist();
void tx80211_freecardlist(struct tx80211_cardlist *in_list);

/* Resolve a card "name" to a card number */
int tx80211_resolvecard(const char *in_str);

/* Resolve an interface to a card number */
int tx80211_resolveinterface(const char *in_str);

/* Get an interface name for a type (used in auto-driver mode) */
char *tx80211_getdrivername(int in_inj);

/* Get the error string */
char *tx80211_geterrstr(struct tx80211 *in_tx);

/* Create and assign a tx80211 system */
int tx80211_init(struct tx80211 *in_tx, const char *in_ifname, int in_injector);

/* Get the capabilities */
int tx80211_getcapabilities(struct tx80211 *in_tx);

/* Open and close an interface */
int tx80211_open(struct tx80211 *in_tx);
int tx80211_close(struct tx80211 *in_tx);

/* Get and set modes */
int tx80211_setmode(struct tx80211 *in_tx, int in_mode);
int tx80211_getmode(struct tx80211 *in_tx);

/* Set "functional" mode ("tx+monitor", etc, vs. absolute mode) */
int tx80211_setfunctionalmode(struct tx80211 *in_tx, int in_fmode);

/* Get and set channels */
int tx80211_setchannel(struct tx80211 *in_tx, int in_chan);
int tx80211_getchannel(struct tx80211 *in_tx);

/* Get and set modulation */
int tx80211_setmodulation(struct tx80211 *in_tx, struct tx80211_packet *in_packet,
		int modulation);
int tx80211_getmodulation(struct tx80211_packet *in_packet);

/* Get and set TX rate */
int tx80211_settxrate(struct tx80211 *in_tx, struct tx80211_packet *in_packet,
		int txrate);
int tx80211_gettxrate(struct tx80211_packet *in_packet);

/* initialize the packet */
void tx80211_initpacket(struct tx80211_packet *in_packet);

/* Transmit a frame */
int tx80211_txpacket(struct tx80211 *in_tx, struct tx80211_packet *in_packet);

/* Selfack */
int tx80211_selfack(struct tx80211 *in_tx, uint8_t *address);

/* Set a local DLT on the tx80211 interface (for the decode functions).  
 * This does NOT set the DLT of the interface, just sets what lorcon 
 * thinks the DLT is */
void tx80211_setlocaldlt(struct tx80211 *in_tx, int in_dlt);

/* Get the DLT of the tx80211 interface */
int tx80211_getdlt(struct tx80211 *in_tx);

/* Decode a packet, filling in the bitmap.  Original packet is NOT 
 * copied and must be retained until end of processing.  DLT must 
 * be set for the tx80211 structure */
int tx80211_decodepkt(int in_dlt, struct tx80211_decode *decoded,
					  const uint8_t *in_packet, int in_length);

#endif
