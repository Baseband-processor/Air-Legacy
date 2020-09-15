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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "tx80211.h"
#include "tx80211_errno.h"
#include "ifcontrol_linux.h"

#include "drv_mac80211.h"

#define TX80211_VERSION 1

unsigned int tx80211_getversion() {
	return TX80211_VERSION;
}

struct tx80211_cardlist *tx80211_getcardlist()
{
	struct tx80211_cardlist *ret = NULL;

	ret =
	    (struct tx80211_cardlist *)malloc(sizeof(struct tx80211_cardlist));
	if (ret == NULL) {
		return NULL;
	}

	ret->cardnames = (char **)malloc(sizeof(char *) * INJ_MAX);
	if (ret->cardnames == NULL) {
		free(ret);
		return NULL;
	}

	ret->descriptions = (char **)malloc(sizeof(char *) * INJ_MAX);
	if (ret->descriptions == NULL) {
		free(ret->cardnames);
		free(ret);
		return NULL;
	}

	ret->capabilities = (int *)malloc(sizeof(int) * INJ_MAX);
	if (ret->capabilities == NULL) {
		free(ret->cardnames);
		free(ret->descriptions);
		free(ret);
		return NULL;
	}

	ret->injnum = (int *)malloc(sizeof(int) * INJ_MAX);
	if (ret->injnum == NULL) {
		free(ret->cardnames);
		free(ret->descriptions);
		free(ret->capabilities);
		free(ret);
		return NULL;
	}

	ret->num_cards = 0;

	/* Too bad there isn't a good way to automate this, fortunately we don't
	 * edit this list all that often.  */

	ret->cardnames[INJ_NODRIVER] = strdup("nodriver");
	ret->descriptions[INJ_NODRIVER] =
	    strdup("No such driver (placeholder)");
	ret->capabilities[INJ_NODRIVER] = 0;
	ret->injnum[INJ_NODRIVER] = INJ_NODRIVER;
	ret->num_cards++;

#ifdef SYS_LINUX
	ret->cardnames[ret->num_cards] = strdup("wlan-ng");
	ret->descriptions[ret->num_cards] =
	    strdup("Wlan-ng Prism2 802.11b (patched)");
	ret->capabilities[ret->num_cards] = tx80211_wlanng_capabilities();
	ret->injnum[ret->num_cards] = INJ_WLANNG;
	ret->num_cards++;

	ret->cardnames[ret->num_cards] = strdup("hostap");
	ret->descriptions[ret->num_cards] = strdup("HostAP Prism2 802.11b");
	ret->capabilities[ret->num_cards] = tx80211_hostap_capabilities();
	ret->injnum[ret->num_cards] = INJ_HOSTAP;
	ret->num_cards++;

	ret->cardnames[ret->num_cards] = strdup("airjack");
	ret->descriptions[ret->num_cards] =
	    strdup("AirJack Prism2 802.11b (defunct)");
	ret->capabilities[ret->num_cards] = tx80211_airjack_capabilities();
	ret->injnum[ret->num_cards] = INJ_AIRJACK;
	ret->num_cards++;

	ret->cardnames[ret->num_cards] = strdup("prism54");
	ret->descriptions[ret->num_cards] = strdup("Prism54 PrismGT 802.11b/g");
	ret->capabilities[ret->num_cards] = tx80211_prism54_capabilities();
	ret->injnum[ret->num_cards] = INJ_PRISM54;
	ret->num_cards++;

	ret->cardnames[ret->num_cards] = strdup("madwifing");
	ret->descriptions[ret->num_cards] = strdup("MADWIFI-ng Atheros 802.11a/b/g");
	ret->capabilities[ret->num_cards] = tx80211_madwifiold_capabilities();
	ret->injnum[ret->num_cards] = INJ_MADWIFING;
	ret->num_cards++;

	ret->cardnames[ret->num_cards] = strdup("madwifiold");
	ret->descriptions[ret->num_cards] = strdup("MADWIFI-old Atheros 802.11a/b/g");
	ret->capabilities[ret->num_cards] = tx80211_madwifiold_capabilities();
	ret->injnum[ret->num_cards] = INJ_MADWIFIOLD;
	ret->num_cards++;

	ret->cardnames[ret->num_cards] = strdup("rtl8180");
	ret->descriptions[ret->num_cards] = strdup("RealTek LAN 8180 802.11b");
	ret->capabilities[ret->num_cards] = tx80211_rtl8180_capabilities();
	ret->injnum[ret->num_cards] = INJ_RTL8180;
	ret->num_cards++;

	ret->cardnames[ret->num_cards] = strdup("rt2570");
	ret->descriptions[ret->num_cards] = strdup("Ralink 2570 802.11b");
	ret->capabilities[ret->num_cards] = tx80211_rt2570_capabilities();
	ret->injnum[ret->num_cards] = INJ_RT2570;
	ret->num_cards++;

	ret->cardnames[ret->num_cards] = strdup("rt2500");
	ret->descriptions[ret->num_cards] = strdup("Ralink 2500 802.11b");
	ret->capabilities[ret->num_cards] = tx80211_rt2500_capabilities();
	ret->injnum[ret->num_cards] = INJ_RT2500;
	ret->num_cards++;

	ret->cardnames[ret->num_cards] = strdup("rt73");
	ret->descriptions[ret->num_cards] = strdup("Ralink 73 802.11g USB");
	ret->capabilities[ret->num_cards] = tx80211_rt73_capabilities();
	ret->injnum[ret->num_cards] = INJ_RT73;
	ret->num_cards++;

	ret->cardnames[ret->num_cards] = strdup("rt61");
	ret->descriptions[ret->num_cards] = strdup("Ralink 61 pre-N PC Card");
	ret->capabilities[ret->num_cards] = tx80211_rt61_capabilities();
	ret->injnum[ret->num_cards] = INJ_RT61;
	ret->num_cards++;

	ret->cardnames[ret->num_cards] = strdup("zd1211rw");
	ret->descriptions[ret->num_cards] = strdup("ZD1211RW 802.11g USB");
	ret->capabilities[ret->num_cards] = tx80211_zd1211rw_capabilities();
	ret->injnum[ret->num_cards] = INJ_ZD1211RW;
	ret->num_cards++;

	ret->cardnames[ret->num_cards] = strdup("bcm43xx");
	ret->descriptions[ret->num_cards] = strdup("Broadcom 43xx");
	ret->capabilities[ret->num_cards] = tx80211_bcm43xx_capabilities();
	ret->injnum[ret->num_cards] = INJ_BCM43XX;
	ret->num_cards++;

	ret->cardnames[ret->num_cards] = strdup("mac80211");
	ret->descriptions[ret->num_cards] = strdup("Linux generic mac80211");
	ret->capabilities[ret->num_cards] = tx80211_mac80211_capabilities();
	ret->injnum[ret->num_cards] = INJ_MAC80211;
	ret->num_cards++;

#endif /* SYS_LINUX */

#ifdef SYS_CYGWIN
	ret->cardnames[ret->num_cards] = strdup("airpcap");
	ret->descriptions[ret->num_cards] = strdup("CACE Technologies AirPcap USB");
	ret->capabilities[ret->num_cards] = tx80211_airpcap_capabilities();
	ret->injnum[ret->num_cards] = INJ_AIRPCAP;
	ret->num_cards++;
#endif /* SYS_CYGWIN */

	return ret;
}

void tx80211_freecardlist(struct tx80211_cardlist *in_list)
{
	int x;

	/* Free the string lists */
	for (x = 0; x < in_list->num_cards; x++) {
		free(in_list->cardnames[x]);
		free(in_list->descriptions[x]);
	}

	free(in_list->cardnames);
	free(in_list->descriptions);
	free(in_list->capabilities);
	free(in_list);
}

int tx80211_resolvecard(const char *in_str)
{
#ifdef SYS_LINUX
	if (!strcasecmp(in_str, "wlan-ng") || !strcasecmp(in_str, "wlanng"))
		return INJ_WLANNG;

	if (!strcasecmp(in_str, "host-ap") || !strcasecmp(in_str, "hostap"))
		return INJ_HOSTAP;

	if (!strcasecmp(in_str, "airjack"))
		return INJ_AIRJACK;

	if (!strcasecmp(in_str, "prism54") || !strcasecmp(in_str, "prismgt"))
		return INJ_PRISM54;

	if (!strcasecmp(in_str, "madwifiold") || 
		!strcasecmp(in_str, "madwifi"))
		return INJ_MADWIFIOLD;

	if (!strcasecmp(in_str, "madwifing") || 
			!strcasecmp(in_str, "madwifi-ng"))
		return INJ_MADWIFING;

	if (!strcasecmp(in_str, "madwifiold") ||
			!strcasecmp(in_str, "madwifi-old"))
		return INJ_MADWIFIOLD;

	if (!strcasecmp(in_str, "rtl8180") || !strcasecmp(in_str, "rt8180"))
		return INJ_RTL8180;

	if (!strcasecmp(in_str, "rt2500") || !strcasecmp(in_str, "rtl2500") ||
	    !strcasecmp(in_str, "rt25k") || !strcasecmp(in_str, "rtl25k"))
		return INJ_RT2500;

	if (!strcasecmp(in_str, "rt2570") || !strcasecmp(in_str, "rtl2570") ||
	    !strcasecmp(in_str, "rt2570"))
		return INJ_RT2570;

	if (!strcasecmp(in_str, "rt73") || !strcasecmp(in_str, "rtl73") ||
		!strcasecmp(in_str, "rt2571"))
		return INJ_RT73;

	if (!strcasecmp(in_str, "rt61") || !strcasecmp(in_str, "rt2561"))
		return INJ_RT61;

	if (!strcasecmp(in_str, "zd1211") || !strcasecmp(in_str, "zd1211rw"))
		return INJ_ZD1211RW;

	if (!strcasecmp(in_str, "bcm43xx"))
		return INJ_BCM43XX;

	if (!strcasecmp(in_str, "ath5k") || !strcasecmp(in_str, "ath9k") ||
		!strcasecmp(in_str, "ath5k_pci") || !strcasecmp(in_str, "ath9k_pci") ||
		!strcasecmp(in_str, "iwlwifi") || !strcasecmp(in_str, "iwlagn") ||
		!strcasecmp(in_str, "iwl-agn") || !strcasecmp(in_str, "iwl3945") ||
		!strcasecmp(in_str, "iwl4965") || !strcasecmp(in_str, "iwl5000") ||
		!strcasecmp(in_str, "mac80211") || !strcasecmp(in_str, "d80211") ||
		!strcasecmp(in_str, "rt2x00") || !strcasecmp(in_str, "rt2400pci") ||
		!strcasecmp(in_str, "rt2500pci") || strcasecmp(in_str, "rt2500usb") ||
		!strcasecmp(in_str, "rt61pci") || strcasecmp(in_str, "rt73usb") ||
		!strcasecmp(in_str, "b43") || !strcasecmp(in_str, "b43legacy") ||
		!strcasecmp(in_str, "rtl8180") || !strcasecmp(in_str, "rtl8187"))
		return INJ_MAC80211;

#endif /* SYS_LINUX */

#ifdef SYS_CYGWIN
	if (!strcasecmp(in_str, "airpcap"))
		return INJ_AIRPCAP;
#endif

	return INJ_NODRIVER;
}

int tx80211_resolveinterface(const char *in_str)
{
#ifdef SYS_LINUX

	char driver[32];
	char *tmpdriver;

	tmpdriver = ifconfig_get_sysdriver(in_str);

	if (tmpdriver == NULL)
		return INJ_NODRIVER;

	/* Clean up so we don't have to deal w/ it on each return */
	snprintf(driver, 32, "%s", tmpdriver);
	free(tmpdriver);

	/* Check for the phy80211 attribute as a shortcut for detecting mac80211 devices */
	if (ifconfig_get_sysattr(in_str, "phy80211"))
		return INJ_MAC80211;

	if (!strcasecmp(driver, "hostap"))
		return INJ_HOSTAP;

	if (!strcasecmp(driver, "prism54"))
		return INJ_PRISM54;

	if (!strcasecmp(driver, "madwifing") || !strcasecmp(driver, "madwifi-ng"))
		return INJ_MADWIFING;

#endif

	return INJ_NODRIVER;
}

char *tx80211_getdrivername(int in_inj)
{
	struct tx80211_cardlist *cardlist = NULL;
	int i;
	char *ret;

	cardlist = tx80211_getcardlist();

	for (i = 1; i < cardlist->num_cards; i++) {
		if (cardlist->injnum[i] == in_inj) {
			ret = strdup(cardlist->cardnames[i]);
			tx80211_freecardlist(cardlist);
			return ret;
		}
	}

	tx80211_freecardlist(cardlist);
	return NULL;
}

char *tx80211_geterrstr(struct tx80211 *in_tx)
{
	return in_tx->errstr;
}

int tx80211_init(struct tx80211 *in_tx, const char *in_ifname, int in_injector)
{
	int ret = TX80211_ENOERR;

	/* Zero the struct entirely */
	memset(in_tx, 0, sizeof(struct tx80211));

	strncpy(in_tx->ifname, in_ifname, MAX_IFNAME_LEN);
	in_tx->injectortype = in_injector;

	switch (in_injector) {

#ifdef SYS_LINUX
	case INJ_WLANNG:
		ret = tx80211_wlanng_init(in_tx);
		break;

	case INJ_AIRJACK:
		ret = tx80211_airjack_init(in_tx);
		break;

	case INJ_PRISM54:
		ret = tx80211_prism54_init(in_tx);
		break;

	case INJ_MADWIFIOLD:
		ret = tx80211_madwifiold_init(in_tx);
		break;

	case INJ_MADWIFING:
		ret = drv_madwifing_init(in_tx);
		break;

	case INJ_HOSTAP:
		ret = tx80211_hostap_init(in_tx);
		break;

	case INJ_RT2500:
		ret = tx80211_rt2500_init(in_tx);
		break;

	case INJ_RT2570:
		ret = tx80211_rt2570_init(in_tx);
		break;

	case INJ_RT73:
		ret = tx80211_rt73_init(in_tx);
		break;

	case INJ_RTL8180:
		ret = tx80211_rtl8180_init(in_tx);
		break;

	case INJ_ZD1211RW:
		ret = tx80211_zd1211rw_init(in_tx);
		break;

	case INJ_BCM43XX:
		ret = tx80211_bcm43xx_init(in_tx);
		break;

	case INJ_MAC80211:
		ret = drv_mac80211_init(in_tx);
		break;

#endif /* SYS_LINUX */

#ifdef SYS_CYGWIN
	case INJ_AIRPCAP:
		ret = tx80211_airpcap_init(in_tx);
		break;
#endif /* SYS_CYGWIN */

	default:
		return TX80211_ENOSUCHINJ;
		break;
	}

	return ret;
}

int tx80211_getcapabilities(struct tx80211 *in_tx)
{
	return in_tx->capabilities;
}

int tx80211_open(struct tx80211 *in_tx)
{
	if (in_tx->open_callthrough == NULL)
		return TX80211_ENOHANDLER;

	return (in_tx->open_callthrough) (in_tx);
}

int tx80211_close(struct tx80211 *in_tx)
{
	if (in_tx->close_callthrough == NULL) 
	{
		snprintf(in_tx->errstr, TX80211_STATUS_MAX, 
				 "Close callthrough handler not implemented");
		return TX80211_ENOHANDLER;
	}

#ifdef SYS_LINUX
	/* See if we need to restore the MAC address */
	if (in_tx->startingmacset == 1) {
		/* Restore the MAC address */
		if (ifconfig_ifupdown(in_tx->ifname, in_tx->errstr,
				TX80211_IFDOWN) < 0) {

			snprintf(in_tx->errstr, TX80211_STATUS_MAX,
					"Failed to place interface %d in the "
					"DOWN state before restoring the MAC "
					"address.", 
					in_tx->ifname);
			return -1;
		}

		if (ifconfig_set_hwaddr(in_tx->extra, in_tx->errstr, 
				in_tx->startingmac) < 0) {
			/* Retain message from set_hwaddr */
			return -1;
		}

		if (ifconfig_ifupdown(in_tx->ifname, in_tx->errstr,
				TX80211_IFUP) < 0) {
			snprintf(in_tx->errstr, TX80211_STATUS_MAX,
					"Failed to place interface %d in the "
					"UP state after restoring the  MAC  "
					"address.", 
					in_tx->ifname);
			return -1;
		}
	}
#endif

	return (in_tx->close_callthrough) (in_tx);
}

int tx80211_setmode(struct tx80211 *in_tx, int in_mode)
{
	fprintf(stderr, "LORCON - tx80211_setmode(...) is deprecated, please use "
			"tx80211_setfunctionalmode(...) instead\n");

	if (in_tx->setmode_callthrough == NULL) 
	{
		snprintf(in_tx->errstr, TX80211_STATUS_MAX, 
				 "Setmode callthrough handler not implemented");
		return TX80211_ENOHANDLER;
	}

	return (in_tx->setmode_callthrough) (in_tx, in_mode);
}

int tx80211_getmode(struct tx80211 *in_tx)
{
	if (in_tx->getmode_callthrough == NULL)
	{
		snprintf(in_tx->errstr, TX80211_STATUS_MAX, 
				 "Getmode callthrough handler not implemented");
		return TX80211_ENOHANDLER;
	}

	return (in_tx->getmode_callthrough) (in_tx);
}

int tx80211_setfunctionalmode(struct tx80211 *in_tx, int in_fmode)
{
	if (in_tx->setfuncmode_callthrough == NULL) 
	{
		snprintf(in_tx->errstr, TX80211_STATUS_MAX, 
				 "Setfunctionalmode callthrough handler not implemented");
		return TX80211_ENOHANDLER;
	}

	return (in_tx->setfuncmode_callthrough) (in_tx, in_fmode);
}

int tx80211_setchannel(struct tx80211 *in_tx, int in_chan)
{
	if (in_tx->setchan_callthrough == NULL)
	{
		snprintf(in_tx->errstr, TX80211_STATUS_MAX, 
				 "Setchannel callthrough handler not implemented");
		return TX80211_ENOHANDLER;
	}

	return (in_tx->setchan_callthrough) (in_tx, in_chan);
}

int tx80211_getchannel(struct tx80211 *in_tx)
{
	if (in_tx->getchan_callthrough == NULL)
	{
		snprintf(in_tx->errstr, TX80211_STATUS_MAX, 
				 "Getchannel callthrough handler not implemented");
		return TX80211_ENOHANDLER;
	}

	return (in_tx->getchan_callthrough) (in_tx);
}

int tx80211_setmodulation(struct tx80211 *in_tx, 
		struct tx80211_packet *in_packet, int modulation)
{
	if (in_tx->injectortype == INJ_NODRIVER) {
		snprintf(in_tx->errstr, TX80211_STATUS_MAX,
				"setmodulation: driver type not intialized");
		return TX80211_ENOINIT;
	}

	if ((tx80211_getcapabilities(in_tx) & TX80211_CAP_SETMODULATION) == 0) {
		snprintf(in_tx->errstr, TX80211_STATUS_MAX,
				"setmodulation: driver does not support setting"
				" the modulation mechanism.");
		return TX80211_ENOTCAPAB;
	}

	in_packet->modulation = modulation;

	return TX80211_ENOERR;
}

int tx80211_getmodulation(struct tx80211_packet *in_packet) {
	return(in_packet->modulation);
}

int tx80211_settxrate(struct tx80211 *in_tx, struct tx80211_packet *in_packet,
		int txrate)
{
	if (in_tx->injectortype == INJ_NODRIVER) {
		snprintf(in_tx->errstr, TX80211_STATUS_MAX,
				"settxrate: driver type not intialized");
		return TX80211_ENOINIT;
	}

	if ((tx80211_getcapabilities(in_tx) & TX80211_CAP_SETRATE) == 0) {
		snprintf(in_tx->errstr, TX80211_STATUS_MAX,
				"setmodulation: driver does not support setting"
				" the TX data rate.");
		return TX80211_ENOTCAPAB;
	}

	in_packet->txrate = txrate;

	return TX80211_ENOERR;
}

int tx80211_gettxrate(struct tx80211_packet *in_packet) {
	return(in_packet->txrate);
}

int tx80211_txpacket(struct tx80211 *in_tx, struct tx80211_packet *in_packet)
{
	if (in_tx->txpacket_callthrough == NULL) 
	{
		snprintf(in_tx->errstr, TX80211_STATUS_MAX, 
				 "txpacket callthrough handler not implemented");
		return TX80211_ENOHANDLER;
	}

	return (in_tx->txpacket_callthrough) (in_tx, in_packet);
}

int tx80211_selfack(struct tx80211 *in_tx, uint8_t *addr)
{
	if (in_tx->selfack_callthrough == NULL) 
	{
		snprintf(in_tx->errstr, TX80211_STATUS_MAX, 
				 "selfack callthrough handler not implemented");
		return TX80211_ENOHANDLER;
	}

	/* See if this card supports the SelfACK capability */
	if ((tx80211_getcapabilities(in_tx) & TX80211_CAP_SELFACK) > 0) {

#ifdef SYS_LINUX
		/* If we haven't already stored it, retrieve the local MAC */
		if (in_tx->startingmacset == 0) {
			/* Store the starting MAC address so we can restore
			 * it later.
			 */
			if (ifconfig_get_hwaddr(in_tx->ifname, in_tx->errstr,
					in_tx->startingmac) < 0) {
				/* retain error from get_hwaddr */
				return -1;
			}
			in_tx->startingmacset = 1;
		}
#endif

#ifdef SYS_CYGWIN
		snprintf(in_tx->errstr, TX80211_STATUS_MAX, "No support for "
				"selfack in CYGWIN");
		return -1;
#endif

	}

	return (in_tx->selfack_callthrough) (in_tx, addr);
}

int tx80211_chan2mhz(int channel) {
	if (channel == 14) {
		return 2484;
	}

	if (channel < 14) {
		return (2407 + (channel * 5));
	}

	return (5000 + (channel * 5));
}

void tx80211_initpacket(struct tx80211_packet *in_packet) 
{
	memset(in_packet, 0, sizeof(struct tx80211_packet));
}

void tx80211_setlocaldlt(struct tx80211 *in_tx, int in_dlt)
{
	in_tx->dlt = in_dlt;
}

int tx80211_getdlt(struct tx80211 *in_tx)
{
	return in_tx->dlt;
}
