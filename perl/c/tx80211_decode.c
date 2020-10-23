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

// Modified by Edoardo Mantovani, 2020
// decode tx80211 packet

#ifdef HAVE_CONFIG_H
#include <lorcon2/config.h>
#endif

#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#ifdef _ARPA_INET_H
#include <arpa/inet.h>
#endif

#include <lorcon2/tx80211.h>

/* for DLT_PRISM_HEADER */
#define WLAN_DEVNAMELEN_MAX	16


/* Define linktype headers if we don't have them in our includes for some  reason */
#ifndef DLT_IEEE802_11
#define DLT_IEEE802_11			105
#endif

#ifndef DLT_PRISM_HEADER
#define DLT_PRISM_HEADER		119
#endif

#ifndef DLT_IEEE802_11_RADIO	
#define DLT_IEEE802_11_RADIO 	127
#endif

#ifndef DLT_IEEE802_11_RADIO_AVS
#define DLT_IEEE802_11_RADIO_AVS 163
#endif

#ifndef DLT_PPI
#define DLT_PPI					192 /* cace PPI */
#endif

#ifndef IEEE80211_RADIOTAP_F_FCS
#define IEEE80211_RADIOTAP_F_FCS        0x10    /* frame includes FCS */
#endif

#ifndef IEEE80211_IOC_CHANNEL
#define IEEE80211_IOC_CHANNEL 0
#endif

/* Older wlan-ng headers */
typedef struct {
	uint32_t did;
	uint16_t status;
	uint16_t len;
	uint32_t data;
} __attribute__((__packed__)) p80211item_uint32_t;

typedef struct {
	uint32_t msgcode;
	uint32_t msglen;
	uint8_t devname[WLAN_DEVNAMELEN_MAX];
	p80211item_uint32_t hosttime;
	p80211item_uint32_t mactime;
	p80211item_uint32_t channel;
	p80211item_uint32_t rssi;
	p80211item_uint32_t sq;
	p80211item_uint32_t signal;
	p80211item_uint32_t noise;
	p80211item_uint32_t rate;
	p80211item_uint32_t istx;
	p80211item_uint32_t frmlen;
} __attribute__((__packed__)) wlan_ng_prism2_header;

/* Wlan-ng AVS headers */
typedef struct {
	uint32_t version;
	uint32_t length;
	uint64_t mactime;
	uint64_t hosttime;
	uint32_t phytype;
	uint32_t channel;
	uint32_t datarate;
	uint32_t antenna;
	uint32_t priority;
	uint32_t ssi_type;
	int32_t ssi_signal;
	int32_t ssi_noise;
	uint32_t preamble;
	uint32_t encoding;
} __attribute__((__packed__)) avs_80211_1_header;

/* CACE PPI headers */
typedef struct {
	uint8_t pph_version;
	uint8_t pph_flags;
	uint16_t pph_len;
	uint32_t pph_dlt;
} __attribute__((__packed__)) ppi_packet_header;

#define PPI_PH_FLAG_ALIGNED		2

typedef struct {
	uint16_t pfh_datatype;
	uint16_t pfh_datalen;
} __attribute__((__packed__)) ppi_field_header;

#define PPI_FIELD_11COMMON		2
#define PPI_FIELD_11NMAC		3
#define PPI_FIELD_11NMACPHY		4
#define PPI_FIELD_SPECMAP		5
#define PPI_FIELD_PROCINFO		6
#define PPI_FIELD_CAPINFO		7

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

/* The radio capture header precedes the 802.11 header. */
typedef struct {
	u_int8_t it_version;
	u_int8_t it_pad;
	u_int16_t it_len;
	u_int32_t it_present; 
} __attribute__((__packed__)) radiotap_header;

int tx80211_decodepkt(int in_dlt, struct tx80211_decode *decoded, const uint8_t *in_packet, int in_length)
{
	avs_80211_1_header *avshdr = (avs_80211_1_header *) in_packet;
	ppi_packet_header *ppihdr = (ppi_packet_header *) in_packet;
	radiotap_header *rtaphdr = (radiotap_header *) in_packet;

	decoded->decode_bitmap = TX80211_DECODE_FLAGSET;
	decoded->pkt_length = in_length;
	decoded->pkt_head = in_packet;
	decoded->pkt_dot11 = NULL;
	decoded->pkt_data = NULL;

	if (in_dlt == DLT_PRISM_HEADER) {
		if (in_length > sizeof(avs_80211_1_header) &&
			ntohl(avshdr->version) == 0x80211001) {
			/* avs */
			if (ntohl(avshdr->length) < in_length) 
				decoded->pkt_dot11 = &(in_packet[ntohl(avshdr->length)]);
		} else if (in_length > sizeof(wlan_ng_prism2_header)) {
			/* prism2 */
			decoded->pkt_dot11 = &(in_packet[sizeof(wlan_ng_prism2_header)]);
		}
	} else if (in_dlt == DLT_PPI) {
		if (in_length > sizeof(ppi_packet_header) &&
			tx80211_le16(ppihdr->pph_len) < in_length) {
			decoded->pkt_dot11 = &(in_packet[tx80211_le16(ppihdr->pph_len)]);
		}
	} else if (in_dlt == DLT_IEEE802_11_RADIO) {
		if (in_length > sizeof(radiotap_header) &&
			tx80211_le16(rtaphdr->it_len) < in_length) {
			decoded->pkt_dot11 = &(in_packet[tx80211_le16(rtaphdr->it_len)]);
		}
	} else if (in_dlt == DLT_IEEE802_11) {
		decoded->pkt_dot11 = in_packet;
	} else {
		return 0;
	}

	return 1;
}
