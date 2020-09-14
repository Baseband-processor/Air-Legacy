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

#ifndef __TX80211_ERRNO_H__
#define __TX80211_ERRNO_H__

/* None */
#define TX80211_ENOERR			0

/* No such injector */
#define TX80211_ENOSUCHINJ		-10

/* No function handler defined */
#define TX80211_ENOHANDLER		-11

/* Set function called before initialization */
#define TX80211_ENOINIT			-12

/* Driver not capable of requested function */
#define TX80211_ENOTCAPAB		-13

/* Not supported */
#define TX80211_ENOTSUPP		-14

/* Out of memory */
#define TX80211_ENOMEM			-15

/* Unable to open interface */
#define TX80211_ENOOPENINT		-16

/* Error setting the channel */
#define TX80211_ENOCHANSET		-17

/* Packet send failed */
#define TX80211_ETXFAILED		-18

/* Close failed */
#define TX80211_ENOCLOSEINT		-19

/* Transmission, no bytes were transmitted. */
#define TX80211_ENOTX			-20

/* Transmission, partial byte count was transmitted */
#define TX80211_EPARTTX			-21

#endif
