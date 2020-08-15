
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "Ctxs.h"



typedef struct lorcon_wep_t          LORCON_WEP;

typedef struct madwi_vaps            MADWIFI_VAPS;

typedef lorcon_multi_error_handler   LORCON_MULTI_ERROR_HANDLER;

typedef struct pcap_pkthdr           PCAP_PKTHDR;

typedef struct  {
        struct lcpa_metapack *prev;
        struct lcpa_metapack *next;
        char type[24];
        int len;
        uint8_t *data;
        int freedata;
}lcpa_metapack;

typedef struct lcpa_metapack             LCPA_META;

typedef struct {
        int type, subtype;
        int reason_code;
        int corrupt;
        const u_char *source_mac, *dest_mac, *bssid_mac, *other_mac;
        unsigned int from_ds, to_ds, frame_protected, fragmented, retry;
        unsigned int qos, sequence, duration, fragment;
        uint16_t capability;
}lorcon_dot11_extra;

typedef lorcon_dot11_extra*        Lorcon_DOT11;

typedef struct {
    const u_char *source_mac;
    const u_char *dest_mac;
    unsigned int llc_type;
}lorcon_dot3_extra;

typedef lorcon_dot3_extra*         Lorcon_DOT3;

typedef lorcon_handler             AirLorconHandler;

typedef lorcon_t                   AirLorcon;
typedef lorcon_driver_t            AirLorconDriver;
typedef lorcon_packet_t            AirLorconPacket;
typedef lorcon_multi_t             AirLorconMulti;
typedef lorcon_multi_interface_t   AirLorconInterface;
typedef lorcon_channel_t           AirLorconChannel;
typedef pcap_t                     Pcap;

typedef struct tx80211        * TX80211;
typedef struct tx80211_packet * TX80211_PACKET;
typedef struct bpf_program    * BPF_PROGRAM;

#include "c/lorcon_driver_t.c"

MODULE = Air::Lorcon2   PACKAGE = Air::Lorcon2
PROTOTYPES: DISABLE

AV *
lorcon_list_drivers()
   INIT:
      lorcon_driver_t *list = lorcon_list_drivers();
      lorcon_driver_t *cur = NULL;
      AV *av = newAV();
   CODE:
      for (cur = list; cur != NULL; cur = cur->next) {
         SV *this = lorcon_driver_t_c2sv(cur);
         av_push(av, this);
      }
      lorcon_free_driver_list(list);
      RETVAL = av;
   OUTPUT:
      RETVAL


const char *
lorcon_get_error( context )
      AirLorcon *context

AirLorconDriver *
lorcon_find_driver( driver )
      const char *driver

AirLorconDriver *
lorcon_auto_driver(interface)
      const char *interface

void
lorcon_free_driver_list(list)
      AirLorconDriver *list

AirLorcon *
lorcon_create(interface, driver)
      const char *interface
      AirLorconDriver *driver
      CODE:
	AirLorcon *context = NULL;
	if (driver->init_func == NULL){
		return NULL;
	}
	context = (AirLorcon *) malloc(sizeof(AirLorcon));
	memset(context, 0, sizeof(AirLorcon));
	snprintf(context->drivername, 32, "%s", driver->name);
   	 context->ifname = strdup(interface);
   	 context->vapname = NULL;
	context->pcap = NULL;
	context->inject_fd = context->ioctl_fd = context->capture_fd = -1;
	context->packets_sent = 0;
	context->packets_recv = 0;
	context->dlt = -1;
	context->channel = -1;
   	 context->channel_ht_flags = LORCON_CHANNEL_BASIC;
	context->errstr[0] = 0;
	context->timeout_ms = 0;
	memset(context->original_mac, 0, 6);
	context->handler_cb = NULL;
	context->handler_user = NULL;
	context->close_cb = NULL;
	context->openinject_cb = NULL;
	context->openmon_cb = NULL;
	context->openinjmon_cb = NULL;
	context->setchan_cb = NULL;
	context->getchan_cb = NULL;
    context->setchan_ht_cb = NULL;
    context->getchan_ht_cb = NULL;
	context->sendpacket_cb = NULL;
	context->getpacket_cb = NULL;
	context->setdlt_cb = NULL;
	context->getdlt_cb = NULL;
	context->getmac_cb = NULL;
	context->setmac_cb = NULL;
    context->pcap_handler_cb = NULL;
	context->wepkeys = NULL;
	if ((*(driver->init_func))(context) < 0) {
		free(context);
		return NULL;
	}
	RETVAL = context;
	OUTPUT:
	  RETVAL


void
lorcon_free(context)
      AirLorcon *context

void
lorcon_set_timeout(context, timeout)
      AirLorcon *context
      int timeout

int
lorcon_get_timeout(context)
      AirLorcon *context

int
lorcon_open_inject(context)
      AirLorcon *context
  

int
lorcon_open_monitor(context)
      AirLorcon *context
	CODE:
	  if (context->openmon_cb == NULL) {
		snprintf(context->errstr, LORCON_STATUS_MAX,  "Driver %s does not support MONITOR mode", context->drivername);
		return LORCON_ENOTSUPP;
	}
	RETVAL =  (*(context->openmon_cb))(context);
	OUTPUT:
		RETVAL

int
lorcon_open_injmon(context)
      AirLorcon *context
      	CODE:
 	if(lorcon_open_injmon(context) == NULL) {
		snprintf(context->errstr, LORCON_STATUS_MAX,  "Driver %s does not support INJMON mode", context->drivername);
		return LORCON_ENOTSUPP;
	}
	RETVAL =  (*(context->openinjmon_cb))(context);
	OUTPUT:
		RETVAL

void 
lorcon_pcap_handler(user,  h, bytes)
	u_char *user
	PCAP_PKTHDR *h
	const u_char *bytes


void
lorcon_set_vap(context, vap)
      AirLorcon *context
      const char *vap

const char *
lorcon_get_vap(context)
      AirLorcon *context

const char *
lorcon_get_capiface(context)
      AirLorcon *context


const char *
lorcon_get_driver_name(context)
      AirLorcon *context

void
lorcon_close(context)
      AirLorcon *context

int
lorcon_get_datalink(context)
      AirLorcon *context

int
lorcon_set_datalink(context, dlt)
      AirLorcon *context
      int dlt

int
lorcon_set_channel(context, channel)
      AirLorcon *context
      int channel

int
lorcon_get_channel(context)
      AirLorcon *context

int 
lorcon_get_hwmac(context, mac)
      AirLorcon *context
      char **mac

int 
lorcon_set_hwmac(context, mac_len, mac)
      AirLorcon *context
      int mac_len
      unsigned char *mac

Pcap *
lorcon_get_pcap(context)
      AirLorcon *context

void 
lorcon_packet_set_freedata(packet, freedata)
  AirLorconPacket *packet
  int freedata

int
lorcon_get_selectable_fd(context)
      AirLorcon *context

int
lorcon_next_ex(context, packet)
      AirLorcon *context
      AirLorconPacket *packet

int
lorcon_set_filter(context, filter)
      AirLorcon *context
      const char *filter

int
lorcon_set_compiled_filter(context, filter)
      AirLorcon *context
      BPF_PROGRAM *filter
      	CODE:
	  if (context->pcap == NULL) {
		snprintf(context->errstr, LORCON_STATUS_MAX, "Driver %s does not define a pcap capture type", context->drivername);
		return LORCON_ENOTSUPP;
	}
	if (pcap_setfilter(context->pcap, filter) < 0) {
		snprintf(context->errstr, LORCON_STATUS_MAX, "%s", pcap_geterr(context->pcap));
		return -1;
	}
	RETVAL = 1;
      	  OUTPUT:
		  RETVAL
		
      
int 
lorcon_loop(context, counter,  callback, user)
  AirLorcon *context
  int counter
  AirLorconHandler callback
  u_char *user
  	CODE:
	int ret;
	if(context->pcap == NULL) {
		snprintf( lorcon_get_error(context), LORCON_STATUS_MAX,  "capture driver %s did not create a pcap context", lorcon_get_driver_name(context) ); // 
		return LORCON_ENOTSUPP; // aka  -255 status code
	}

	context->handler_cb = callback;
	context->handler_user = user;
	ret = pcap_loop(context->pcap, counter,  (u_char *) context);
    RETVAL =  ret;
	OUTPUT:
	  RETVAL
	  

      
int 
lorcon_dispatch(context, counter,  callback, user)
   AirLorcon *context
   int counter
   AirLorconHandler callback
   u_char *user
   
void
lorcon_breakloop(context)
  AirLorcon *context


int
lorcon_inject(context, packet)
      AirLorcon *context
      AirLorconPacket *packet

int
lorcon_send_bytes(context, length, bytes)
      AirLorcon *context
      int length
      u_char *bytes

unsigned long int
lorcon_get_version()

int
lorcon_add_wepkey(context, bssid, key, length)
      AirLorcon *context
      u_char *bssid
      u_char *key
      int length
	BOOT:
	  	if (length > 26){
		return -1;
	}
	CODE:
	LORCON_WEP *wep;
	wep = (	LORCON_WEP *) malloc(sizeof(LORCON_WEP) );
	memcpy(wep->bssid, bssid, 6);
	memcpy(wep->key, key, length);
	wep->len = length;
	wep->next = context->wepkeys;
	context->wepkeys = wep;
	RETVAL = 1;
	  OUTPUT:
	    RETVAL


void 
lorcon_set_useraux(context, aux)
  AirLorcon *context
  void *aux

void  
lorcon_get_useraux(context)
  AirLorcon *context
    CODE:
	RETVAL = (context->userauxptr);	
	OUTPUT:
	  RETVAL
	  
void  
lorcon_packet_free(packet)
  AirLorconPacket *packet

int 
lorcon_packet_decode(packet)
  AirLorconPacket *packet


AirLorconPacket *
lorcon_packet_decrypt(context, packet) 
  AirLorcon *context
  AirLorconPacket *packet
	CODE:
	AirLorconPacket *ret;
	lorcon_wep_t *wepidx = context->wepkeys;
	struct lorcon_dot11_extra *extra = (Lorcon_DOT11 *) packet->extra_info;
	u_char pwd[LORCON_WEPKEY_MAX + 3], keyblock[256];
	int pwdlen = 3;
	int kba = 0, kbb = 0;
if (packet->extra_info == NULL || packet->extra_type != LORCON_PACKET_EXTRA_80211 ||
		packet->packet_data == NULL || packet->length_data < 7)
		return NULL;
	while (wepidx) {
		if (memcmp(extra->bssid_mac, wepidx->bssid, 6) == 0){
			break;
		}
		wepidx = wepidx->next;
		RETVAL = wepidx;
	}
	if(wepidx == NULL){
		return( NULL );
	}
	  OUTPUT:
		RETVAL //return null if wepIDX is null
			
void  
lorcon_packet_set_channel(packet, channel)
  AirLorconPacket *packet
  int channel

AirLorconPacket *
lorcon_packet_from_dot3(bssid, dot11_direction, data, length)
  u_char *bssid
  int dot11_direction
  u_char *data
  int length

int 
lorcon_packet_to_dot3(packet, data)
  AirLorconPacket *packet
  u_char *data

		
int 
lorcon_ifup( context )
  AirLorcon *context


const u_char *
lorcon_packet_get_source_mac(packet)
  AirLorconPacket *packet

void
lcpf_randmac(addr, valid)
  uint8_t *addr
  int valid

const u_char *
lorcon_packet_get_dest_mac(packet)
  AirLorconPacket *packet

const u_char *
lorcon_packet_get_bssid_mac(packet)
  AirLorconPacket *packet

int 
lorcon_ifdown( context )
  AirLorcon *context

int
lorcon_set_complex_channel(context, channel)
  AirLorcon *context
  AirLorconChannel *channel

int
lorcon_get_complex_channel( context, channel )
  AirLorcon *context
  AirLorconChannel *channel

int 
lorcon_parse_ht_channel( in_chanstr, channel )
  const char *in_chanstr
  AirLorconChannel *channel

AirLorconMulti *
lorcon_multi_create()

void
lorcon_multi_free(ctx, free_interfaces)
  AirLorconMulti *ctx
  int free_interfaces

int
lorcon_multi_add_interface(ctx, lorcon_intf)
  AirLorconMulti *ctx
  AirLorcon *lorcon_intf

void 
lorcon_multi_del_interface(ctx, lorcon_intf, free_interface)
  AirLorconMulti *ctx
  AirLorcon *lorcon_intf
  int free_interface

AirLorconInterface *
lorcon_multi_get_interfaces(ctx)
  AirLorconMulti *ctx

AirLorconInterface *
lorcon_multi_get_next_interface(ctx, intf)
  AirLorconMulti *ctx
  AirLorconInterface *intf

AirLorcon *
lorcon_multi_interface_get_lorcon(intf)
  AirLorconInterface *intf

void 
lorcon_multi_set_interface_error_handler(ctx, lorcon_interface, handler, aux)
  AirLorconMulti *ctx
  AirLorcon *lorcon_interface
  LORCON_MULTI_ERROR_HANDLER handler
  void *aux

void
lorcon_multi_remove_interface_error_handler(ctx, lorcon_interface)
  AirLorconMulti *ctx
  AirLorcon *lorcon_interface

int
lorcon_multi_loop(ctx, counter, callback, user)
  AirLorconMulti *ctx
  int counter
  AirLorconHandler callback
  unsigned char *user

AirLorconDriver *
drv_madwifing_listdriver(drv)
   AirLorconDriver * drv
     
int 
drv_madwifing_init(context) 
  AirLorcon *context

int
lorcon_airjack_init(in_tx)
  AirLorcon *in_tx

AirLorconDriver *
lorcon_airjack_listdriver(drv)
   AirLorconDriver *drv

int 
aj_setmonitor(ifname, rfmonset)
  char *ifname
  int rfmonset

int 
aj_setmode(ifname,  mode)
  char *ifname
  int mode

int 
aj_setchannel(ifname,channel)
  char *ifname
  int channel

int 
aj_setmac(ifname, mac)
  char *ifname
  uint8_t *mac

int 
aj_xmitframe(ifname, xmit, len, errstr)
  char *ifname
  uint8_t *xmit
  int len
  char *errstr

int
aj_recvframe(ifname, buf, len)
  char *ifname
  uint8_t *buf
  int len

int 
tx80211_airpcap_init(in_tx)
  TX80211 *in_tx
  
int
tx80211_airpcap_capabilities()

int
airpcap_open(in_tx)
  TX80211 *in_tx

int
airpcap_send(in_tx,  in_pkt)
  TX80211 *in_tx
  TX80211_PACKET *in_pkt

int
airpcap_setfuncmode(in_tx, funcmode)
  TX80211 *in_tx
  int funcmode
  
int 
airpcap_close(in_tx)
  TX80211 *in_tx
  
int
airpcap_setmode(in_tx, mode)
  TX80211 *in_tx
  int mode

int 
nl80211_connect(interface, nl_sock, nl80211_id, if_index, errstr)
     const char *interface
     void **nl_sock
     int *nl80211_id
     int *if_index
     char *errstr
     
void
nl80211_disconnect(nl_sock)
     void *nl_sock

int 
nl80211_createvif(interface, newinterface, in_flags, flags_sz, errstr)
     const char *interface
     const char *newinterface
     unsigned int *in_flags
     unsigned int * flags_sz
     char *errstr

int
nl80211_setchannel(interface, channel, chmode, errstr)
     const char *interface
     int channel
     unsigned int chmode
     char *errstr

int
nl80211_setchannel_cache(ifidx, nl_sock, nl80211_id, channel, chmode, errstr)
        int ifidx
        void *nl_sock
        int nl80211_id
        int channel 
        unsigned int chmode
        char *errstr

int
nl80211_setfrequency(interface, control_freq, chan_width, center_freq1, center_freq2, errstr)
        const char *interface 
        unsigned int control_freq
        unsigned int chan_width
        unsigned int center_freq1
        unsigned int center_freq2
        char *errstr
#int
#nl80211_setfrequency_cache(ifidx, nl_sock, nl80211_id, control_freq, chan_width, center_freq1, center_freq2, errstr)
 #  int ifidx
  # void *nl_sock
  # int nl80211_id
  # unsigned int control_freq
  # unsigned int chan_width
  # unsigned int center_freq1 
 #  unsigned int center_freq2
#   char *errstr

char *
nl80211_find_parent(interface)
   const char *interface

int
iwconfig_set_ssid(in_dev, errstr, in_essid)
   const char *in_dev
   char *errstr
   char *in_essid
                         
int
iwconfig_get_ssid(in_dev, errstr, in_essid)
   const char *in_dev   
   char *errstr
   char *in_essid

int
iwconfig_get_name(in_dev, errstr, in_name)
   const char *in_dev
   char *errstr
   char *in_name
   
int
iwconfig_get_channel(in_dev, errstr)
   const char *in_dev
   char *errstr

int
iwconfig_set_channel(in_dev, errstr, in_ch)
   const char *in_dev
   char *errstr
   int in_ch

int 
iwconfig_get_mode(in_dev, errstr)
   const char *in_dev
   char *errstr
                         
int
iwconfig_set_mode(in_dev, errstr, in_mode)
   const char *in_dev
   char *errstr
   int in_mode

int
drv_mac80211_init(a)
     AirLorcon *a
     
AirLorconDriver *
drv_mac80211_listdriver(a)
     AirLorconDriver *a
     
int
tx80211_hostap_init(in_tx)
     TX80211 *in_tx

int
tx80211_hostap_capabilities()
     
     
#int 
#drv_tuntap_init(context)
#   AirLorcon *context
#     CODE:
#	lorcon_open_inject(context) =  tuntap_openmon_cb;
#	lorcon_open_monitor(context) = tuntap_openmon_cb;
#	lorcon_open_injmon(context) =  tuntap_openmon_cb;
#	RETVAL = 1;
#	  OUTPUT:
#	RETVAL

AirLorconDriver *
drv_tuntap_listdriver(drv)
   AirLorconDriver *drv
	CODE:
 	AirLorconDriver *d = (AirLorconDriver *) malloc(sizeof(AirLorconDriver));

	d->name = strdup("tuntap");
	d->details = strdup("Linux tuntap virtual interface drivers");
	d->init_func = drv_tuntap_init;
	d->probe_func = NULL;

	RETVAL =  d;
	OUTPUT:
	  RETVAL

int
drv_file_init(init)
     AirLorcon *init

#int
#drv_rtfile_init(init)
 #    AirLorcon *init
     
AirLorconDriver *
drv_file_listdriver(drv)
     AirLorconDriver *drv

LCPA_META *
lcpa_init()

LCPA_META *
lcpa_append_copy(in_pack, in_type, in_length, in_data)
              LCPA_META *in_pack
              const char *in_type
              int in_length
              uint8_t *in_data

LCPA_META *
lcpa_append(in_pack, in_type, in_length, in_data)
              LCPA_META *in_pack
              const char *in_type
              int in_length
              uint8_t *in_data

LCPA_META *
lcpa_insert(in_pack, in_type, in_length, in_data)
        LCPA_META *in_pack
        const char *in_type
        int in_length
        uint8_t *in_data
        CODE:
      RETVAL = lcpa_insert(&in_pack, &in_type, in_length, &in_data);
   OUTPUT:
      RETVAL
      
LCPA_META *
lcpa_find_name(in_head, in_type)
              LCPA_META *in_head
              const char *in_type
         CODE:
      RETVAL = lcpa_find_name(&in_head, &in_type);
   OUTPUT:
      RETVAL
      
void
lcpa_replace_copy(in_pack, in_type, in_length, in_data)
              LCPA_META *in_pack
              const char *in_type
              int in_length
              uint8_t *in_data
              
void
lcpa_replace(in_pack, in_type, in_length, in_data)
        LCPA_META *in_pack
        const char *in_type
        int in_length
        uint8_t *in_data
        
MADWIFI_VAPS *
madwifing_list_vaps(interface_name, errorstring)
	const char *interface_name
	char *errorstring

void 
madwifing_free_vaps(in_vaplist)
	MADWIFI_VAPS *in_vaplist

int 
madwifing_destroy_vap(interface_name, errorstring)
	const char *interface_name
	char *errorstring

int 
madwifing_build_vap(interface_name, errorstring, vapname, retvapname, vapmode, vapflags)
	const char *interface_name
	char *errorstring
	const char *vapname
	char *retvapname
	int vapmode
	int vapflags

int 
madwifing_setdevtype(interface_name, devtype, errorstring)
	const char *interface_name
	char *devtype
	char *errorstring

char *
madwifing_find_parent(vaplist)
	MADWIFI_VAPS *vaplist

char *
ifconfig_get_sysdriver(in_dev)
	const char *in_dev

int
ifconfig_get_sysattr(in_dev, attr)
	const char *in_dev
	const char *attr

int 
ifconfig_set_flags(in_dev, errorstring, flags)
	const char *in_dev
	char *errorstring
	short flags

int 
ifconfig_delta_flags(in_dev, errorstring,  flags)
	const char *in_dev
	char *errorstring
	short flags

int 
ifconfig_get_flags(in_dev, errorstring, flags)
	const char *in_dev
	char *errorstring
	short *flags

int 
ifconfig_get_hwaddr(in_dev, errorstring, ret_hwaddr)
	const char *in_dev
	char *errorstring
	uint8_t * ret_hwaddr

int 
ifconfig_set_hwaddr(in_dev, errorstring, in_hwaddr)
	const char *in_dev
	char *errorstring
	uint8_t * in_hwaddr

int 
ifconfig_set_mtu(in_dev, errorstring, in_mtu)
	const char *in_dev
	char *errorstring
	uint16_t in_mtu

int 
ifconfig_ifupdown(in_dev, errorstring,  devup)
	const char *in_dev
	char *errorstring
	int devup

int 
wtinj_send(wtinj, in_pkt)
	TX80211 *wtinj
	TX80211_PACKET *in_pkt

int 
wtinj_open(wtinj)
	TX80211 *wtinj

int 
wtinj_close(wtinj)
	TX80211 *wtinj

int 
wtinj_setchannel(wtinj, channel)
	TX80211 *wtinj
	int channel

int 
wtinj_getchannel(wtinj)
	TX80211 *wtinj

int 
wtinj_setmode(wtinj, mode)
	TX80211 *wtinj
	int mode

int 
wtinj_getmode(wtinj)
	TX80211  *wtinj

int 
wtinj_setfuncmode(wtinj, funcmode)
	TX80211 *wtinj
	int funcmode

int 
wtinj_selfack(wtinj, addr)
	TX80211 *wtinj
	uint8_t *addr

int 
tx80211_zd1211rw_capabilities()
	CODE:
	  RETVAL = (TX80211_CAP_SNIFF | TX80211_CAP_TRANSMIT | TX80211_CAP_SEQ | TX80211_CAP_BSSTIME | TX80211_CAP_FRAG | TX80211_CAP_DURID | TX80211_CAP_SNIFFACK | TX80211_CAP_DSSSTX);
	OUTPUT:
	  RETVAL
	  
int 
tx80211_zd1211rw_init(in_tx)
	TX80211 *in_tx
	CODE:
	  TX80211 *in_tx
	in_tx->capabilities = tx80211_zd1211rw_capabilities();
	in_tx->open_callthrough = &wtinj_open;
	in_tx->close_callthrough = &wtinj_close;
	in_tx->setmode_callthrough = &wtinj_setmode;
	in_tx->getmode_callthrough = &wtinj_getmode;
	in_tx->getchan_callthrough = &wtinj_getchannel;
	in_tx->setchan_callthrough = &wtinj_setchannel;
	in_tx->txpacket_callthrough = &tx80211_zd1211rw_send;
	in_tx->setfuncmode_callthrough = &wtinj_setfuncmode;
	RETVAL = 0;
	  OUTPUT:
	    RETVAL
int 
tx80211_zd1211rw_send(in_tx, in_pkt)
	TX80211 *in_tx
	TX80211_PACKET *in_pkt


