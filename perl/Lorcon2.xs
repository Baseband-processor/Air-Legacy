
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

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
#include <lorcon2/lorcon_int.h>
#include <lorcon2/nl80211_control.h>
#include <lorcon2/lorcon_packasm.h>

typedef lorcon_t                   NetLorcon;
typedef lorcon_driver_t            NetLorconDriver;
typedef lorcon_packet_t            NetLorconPacket;
typedef lorcon_multi_t             NetLorconMulti;
typedef lorcon_multi_interface_t   NetLorconInterface;
typedef lorcon_channel_t           NetLorconChannel;
typedef pcap_t                     Pcap;

typedef struct tx80211        TX80211;
typedef struct tx80211_packet TX80211_PACKET;

#include "c/lorcon_driver_t.c"

MODULE = Net::Lorcon2   PACKAGE = Net::Lorcon2
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
      NetLorcon *context

NetLorconDriver *
lorcon_find_driver( driver )
      const char *driver

NetLorconDriver *
lorcon_auto_driver(interface)
      const char *interface

void
lorcon_free_driver_list(list)
      NetLorconDriver *list

NetLorcon *
lorcon_create(interface, driver)
      const char *interface
      NetLorconDriver *driver

void
lorcon_free(context)
      NetLorcon *context

void
lorcon_set_timeout(context, timeout)
      NetLorcon *context
      int timeout

int
lorcon_get_timeout(context)
      NetLorcon *context

int
lorcon_open_inject(context)
      NetLorcon *context

int
lorcon_open_monitor(context)
      NetLorcon *context

int
lorcon_open_injmon(context)
      NetLorcon *context

void
lorcon_set_vap(context, vap)
      NetLorcon *context
      const char *vap

const char *
lorcon_get_vap(context)
      NetLorcon *context

const char *
lorcon_get_capiface(context)
      NetLorcon *context


const char *
lorcon_get_driver_name(context)
      NetLorcon *context

void
lorcon_close(context)
      NetLorcon *context

int
lorcon_get_datalink(context)
      NetLorcon *context

int
lorcon_set_datalink(context, dlt)
      NetLorcon *context
      int dlt

int
lorcon_set_channel(context, channel)
      NetLorcon *context
      int channel

int
lorcon_get_channel(context)
      NetLorcon *context

int 
lorcon_get_hwmac(context, mac)
      NetLorcon *context
      char **mac

int 
lorcon_set_hwmac(context, mac_len, mac)
      NetLorcon *context
      int mac_len
      unsigned char *mac

Pcap *
lorcon_get_pcap(context)
      NetLorcon *context

void 
lorcon_packet_set_freedata(packet, freedata)
  NetLorconPacket *packet
  int freedata

int
lorcon_get_selectable_fd(context)
      NetLorcon *context

int
lorcon_next_ex(context, packet)
      NetLorcon *context
      NetLorconPacket *packet

int
lorcon_set_filter(context, filter)
      NetLorcon *context
      const char *filter

#int
#lorcon_set_compiled_filter(context, filter)
      #NetLorcon *context
      #struct bpf_program *filter

#int 
#lorcon_loop(context, count,  callback, user)
#  NetLorcon *context
#  int count
#  NetLorconHandler callback
#  u_char *user

#int 
#lorcon_dispatch(lorcon_t *context, int count,  callback, u_char *user);

void
lorcon_breakloop(context);
  NetLorcon *context


int
lorcon_inject(context, packet)
      NetLorcon *context
      NetLorconPacket *packet

int
lorcon_send_bytes(context, length, bytes)
      NetLorcon *context
      int length
      u_char *bytes

unsigned long int
lorcon_get_version()

int
lorcon_add_wepkey(context, bssid, key, length)
      NetLorcon *context
      u_char *bssid
      u_char *key
      int length

void 
lorcon_set_useraux(context, aux)
  NetLorcon *context
  void *aux

void  
lorcon_get_useraux(context)
  NetLorcon *context

void  
lorcon_packet_free(packet)
  NetLorconPacket *packet

int 
lorcon_packet_decode(packet)
  NetLorconPacket *packet

void  
lorcon_packet_set_channel(packet, channel)
  NetLorconPacket *packet
  int channel

NetLorconPacket *
lorcon_packet_from_dot3(bssid, dot11_direction, data, length)
  u_char *bssid
  int dot11_direction
  u_char *data
  int length

int 
lorcon_packet_to_dot3(packet, data)
  NetLorconPacket *packet
  u_char *data


int 
lorcon_ifup( context )
  NetLorcon *context


const u_char *
lorcon_packet_get_source_mac(packet)
  NetLorconPacket *packet

void
lcpf_randmac(addr, valid)
  uint8_t *addr
  int valid

const u_char *
lorcon_packet_get_dest_mac(packet)
  NetLorconPacket *packet

const u_char *
lorcon_packet_get_bssid_mac(packet)
  NetLorconPacket *packet

int 
lorcon_ifdown( context );
  NetLorcon *context

int
lorcon_set_complex_channel(context, channel)
  NetLorcon *context
  NetLorconChannel *channel

int
lorcon_get_complex_channel( context, channel )
  NetLorcon *context
  NetLorconChannel *channel

int 
lorcon_parse_ht_channel( in_chanstr, channel )
  const char *in_chanstr
  NetLorconChannel *channel

NetLorconMulti *
lorcon_multi_create()

void
lorcon_multi_free(ctx, free_interfaces)
  NetLorconMulti *ctx
  int free_interfaces

int
lorcon_multi_add_interface(ctx, lorcon_intf)
  NetLorconMulti *ctx
  NetLorcon *lorcon_intf

void 
lorcon_multi_del_interface(ctx, lorcon_intf, free_interface)
  NetLorconMulti *ctx
  NetLorcon *lorcon_intf
  int free_interface

NetLorconInterface *
lorcon_multi_get_interfaces(ctx)
  NetLorconMulti *ctx

NetLorconInterface *
lorcon_multi_get_next_interface(ctx, intf)
  NetLorconMulti *ctx
  NetLorconInterface *intf

NetLorcon *
lorcon_multi_interface_get_lorcon(intf)
  NetLorconInterface *intf

#void 
#lorcon_multi_set_interface_error_handler(ctx, lorcon_interface)
 # NetLorconMulti *ctx
  #NetLorcon *lorcon_interface

void
lorcon_multi_remove_interface_error_handler(ctx, lorcon_interface)
  NetLorconMulti *ctx
  NetLorcon *lorcon_interface

#int
#lorcon_multi_loop(ctx, count, callback, user)
 # NetLorconMulti *ctx
  #int count
  ## callback
  #unsigned char *user

#NetLorconDriver *
#drv_madwifing_listdriver()

int 
drv_madwifing_init(context) 
  NetLorcon *context

int
lorcon_airjack_init(in_tx)
  NetLorcon *in_tx

#NetLorconDriver *
#lorcon_airjack_listdriver()

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
#   int ifidx
#   void *nl_sock
#   int nl80211_id
#   unsigned int control_freq
#   unsigned int chan_width
#   unsigned int center_freq1 
#   unsigned int center_freq2
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
