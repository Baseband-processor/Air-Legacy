#ifndef __CTXS_H
#define __CTXS_H

// Made by Edoardo Mantovani, 2020
// import libraries

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include <string.h>
#include <math.h>
#include <assert.h>
#include <unistd.h>
#include <lorcon2/lorcon.h>
#include <lorcon2/lorcon_packet.h>
#include <lorcon2/lorcon_multi.h>
#include <lorcon2/lorcon_ieee80211.h>
#include <lorcon2/lorcon_forge.h>
#include <lorcon2/drv_madwifing.h>
#include <lorcon2/airpinject.h>
#include <lorcon2/drv_airjack.h>
#include <lorcon2/drv_file.h>
#include <lorcon2/drv_mac80211.h>
#include <lorcon2/drv_tuntap.h>
#include <lorcon2/iwcontrol.h>
#include <lorcon2/ifcontrol_linux.h>
#include <lorcon2/lorcon_int.h>
#include <lorcon2/nl80211_control.h>
#include <lorcon2/lorcon_packasm.h>
#include <lorcon2/sha1.h>
#include <lorcon2/reaver.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <pcap.h>
#include "ppport.h"

#ifdef AIRCRACK_NG_CRYPTO_ENGINE_H
  #include <aircrack-ng/ce-wpa/crypto_engine.h>
#endif

#ifdef #ifdef _CRYPTO_H
  #include <aircrack-ng/crypto/crypto.h>
#endif

#endif /* __CTXS_H */
