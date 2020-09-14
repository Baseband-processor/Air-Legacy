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

#ifndef __TX80211_PACKET_H__
#define __TX80211_PACKET_H__

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

/* Modulation flags we use for LORCON */
enum tx80211_mod_flags {
	TX80211_MOD_DEFAULT=0,
	TX80211_MOD_FHSS,
	TX80211_MOD_DSSS,
	TX80211_MOD_OFDM,
	TX80211_MOD_TURBO,
	TX80211_MOD_MIMO,
	TX80211_MOD_MIMOGF
};

/* Channel flags for radiotap */
#define TX80211_RTAP_CHAN_TURBO    0x0010   /* Turbo channel */
#define TX80211_RTAP_CHAN_CCK      0x0020   /* CCK channel */
#define TX80211_RTAP_CHAN_OFDM     0x0040   /* OFDM channel */
#define	TX80211_RTAP_CHAN_2GHZ	   0x0080   /* 2 GHz spectrum channel. */
#define TX80211_RTAP_CHAN_5GHZ     0x0100   /* 5 GHz spectrum channel */
#define TX80211_RTAP_CHAN_PASSIVE  0x0200   /* Only passive scan allowed */
#define	TX80211_RTAP_CHAN_DYN	   0x0400   /* Dynamic CCK-OFDM channel */
#define	TX80211_RTAP_CHAN_GFSK	   0x0800   /* GFSK channel (FHSS PHY) */
#define	TX80211_RTAP_CHAN_STURBO   0x2000   /* 11a static turbo channel only */

/* Useful combinations of channel characteristics, borrowed from Ethereal */
#define TX80211_RTAP_CHAN_A \
	(TX80211_RTAP_CHAN_5GHZ | TX80211_RTAP_CHAN_OFDM)
#define TX80211_RTAP_CHAN_B \
	(TX80211_RTAP_CHAN_2GHZ | TX80211_RTAP_CHAN_CCK)
#define TX80211_RTAP_CHAN_G \
	(TX80211_RTAP_CHAN_2GHZ | TX80211_RTAP_CHAN_DYN)
#define TX80211_RTAP_CHAN_TA \
	(TX80211_RTAP_CHAN_5GHZ | TX80211_RTAP_CHAN_OFDM | \
	TX80211_RTAP_CHAN_TURBO)
#define TX80211_RTAP_CHAN_TG \
	(TX80211_RTAP_CHAN_2GHZ | TX80211_RTAP_CHAN_DYN  | \
	TX80211_RTAP_CHAN_TURBO)

/* Values are in a quantity of 500 Kbps increments */
#define TX80211_RATE_DEFAULT 0
#define TX80211_RATE_1MB 2 
#define TX80211_RATE_2MB 4 
#define TX80211_RATE_5_5MB 11
#define TX80211_RATE_6MB 12
#define TX80211_RATE_9MB 18
#define TX80211_RATE_11MB 22 
#define TX80211_RATE_12MB 24 
#define TX80211_RATE_18MB 36 
#define TX80211_RATE_24MB 48 
#define TX80211_RATE_36MB 72 
#define TX80211_RATE_48MB 96 
#define TX80211_RATE_54MB 108
#define TX80211_RATE_108MB 216


struct tx80211_packet {
	uint8_t modulation;
	uint8_t txrate;
	uint8_t *packet;
	int plen;
};
typedef struct tx80211_packet tx80211_packet_t;

#endif
