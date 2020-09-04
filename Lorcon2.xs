#define INT_MAX    2147483647
#define LORCON_CHANNEL_BASIC    0
#define LORCON_CHANNEL_HT20     1
#define LORCON_CHANNEL_HT40P    2
#define LORCON_CHANNEL_HT40M    3
#define LORCON_CHANNEL_5MHZ     4
#define LORCON_CHANNEL_10MHZ    5
#define LORCON_CHANNEL_VHT80    6
#define LORCON_CHANNEL_VHT160   7
#define LORCON_CHANNEL_VHT8080  8
#define MAX_IFNAME_LEN		32
#define LORCON_WEPKEY_MAX	26
#define LORCON_PACKET_EXTRA_NONE		0
#define LORCON_PACKET_EXTRA_80211		1
#define LORCON_PACKET_EXTRA_8023		2
#define LORCON_STATUS_MAX	1024
#define LORCON_MAX_PACKET_LEN	8192
#define LORCON_ENOTSUPP -255
#define	IFNAMSIZ	16
#define	IFALIASZ	256
#define TX80211_IFUP 1
#define TX80211_IFDOWN 0
#define WLAN_FC_TYPE_MGMT 0
#define WLAN_FC_TYPE_CTRL 1
#define WLAN_FC_TYPE_DATA 2
#define WLAN_FC_SUBTYPE_DATA        0
#define WLAN_FC_SUBTYPE_ASSOCREQ    0
#define WLAN_FC_SUBTYPE_ASSOCRESP   1
#define WLAN_FC_SUBTYPE_REASSOCREQ  2
#define WLAN_FC_SUBTYPE_REASSOCRESP 3
#define WLAN_FC_SUBTYPE_PROBEREQ    4
#define WLAN_FC_SUBTYPE_PROBERESP   5
#define WLAN_FC_SUBTYPE_BEACON      8
#define WLAN_FC_SUBTYPE_ATIM        9
#define WLAN_FC_SUBTYPE_DISASSOC    10
#define WLAN_FC_SUBTYPE_AUTH        11
#define WLAN_FC_SUBTYPE_DEAUTH      12
#define WLAN_FC_SUBTYPE_QOSDATA     8

#define TX80211_CAP_CTRL	64
#define TX80211_CAP_SELFACK	512
#define SIOCDEVPRIVATE  0x89F0
#define SIOCAJSMODE SIOCDEVPRIVATE

#define TX80211_CAP_SNIFF 1
#define TX80211_CAP_TRANSMIT 2
#define TX80211_CAP_SEQ 4
#define TX80211_CAP_BSSTIME 8
#define TX80211_CAP_FRAG 32
#define TX80211_CAP_DURID 128
#define TX80211_CAP_SNIFFACK 256
#define TX80211_CAP_DSSSTX 2048
#define TX80211_CAP_SETRATE 16384
#define TX80211_CAP_SETMODULATION 32768

#define INJ_NODRIVER    0
#define INJ_WLANNG  	1
#define INJ_HOSTAP  	2
#define INJ_AIRJACK 	3
#define INJ_PRISM54 	4
#define INJ_MADWIFIOLD 	5
#define INJ_MADWIFING  	6
#define INJ_RTL8180     7
#define INJ_RT2500	8
#define INJ_RT2570	9
#define INJ_RT73	10
#define INJ_AIRPCAP	11
#define INJ_RT61	12
#define INJ_ZD1211RW	13
#define INJ_BCM43XX     14
#define INJ_MAC80211	15

#define __FD_ISSET(d, set) \
  ((__FDS_BITS (set)[__FD_ELT (d)] & __FD_MASK (d)) != 0)

#define FD_ISSET(fd, fdsetp)    __FD_ISSET (fd, fdsetp)

#define TX80211_ENOTX -20
#define TX80211_EPARTTX -21

#define FD_ZERO(fdsetp)          __FD_ZERO (fdsetp) 
#define LORCON_DOT11_DIR_FROMDS		1
#define LORCON_DOT11_DIR_TODS		2
#define LORCON_DOT11_DIR_INTRADS	3
#define LORCON_DOT11_DIR_ADHOCDS	4

#define TX80211_STATUS_MAX  1
#define AIRPCAP_ERRBUF_SIZE 512

#define BIT(x) (1 << (x))
#define WLAN_FC_TODS                BIT(0)
#define WLAN_FC_FROMDS              BIT(1)
#define WLAN_FC_MOREFRAG            BIT(2)
#define WLAN_FC_RETRY               BIT(3)
#define WLAN_FC_PWRMGT              BIT(4)
#define WLAN_FC_MOREDATA            BIT(5)
#define WLAN_FC_ISWEP               BIT(6)
#define WLAN_FC_ORDER               BIT(7)
#define PCAP_ERRBUF_SIZE 	    256
#define PCAP_ERROR 		    -1

#define lorcon_hton16(x) (x)

#define ETH_P_ECONET	0x0018
#define ETH_P_80211_RAW (ETH_P_ECONET + 1)
#define ARPHDR_RADIOTAP "803"


#define SIOC80211IFCREATE (SIOCDEVPRIVATE+7)

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"


#include "Ctxs.h"

typedef struct {
	__u32		nlmsg_len;	
	__u16		nlmsg_type;	
	__u16		nlmsg_flags;
	__u32		nlmsg_seq;	
	__u32		nlmsg_pid;	
}nlmsghdr;

typedef struct nlmsghdr NLMSGHDR;

typedef struct nlmsgerr {
	int	error;
	NLMSGHDR *msg;
};

typedef struct  nlmsgerr NLMSGERR;

typedef struct {
	uint16_t mode;		
	uint8_t ownmac[6];		
	uint8_t monitor;		
	uint8_t channel;		
	uint8_t essid[33];		
}aj_config;

typedef struct aj_config AJ_CONF;

typedef struct tx80211_cardlist{
	char **cardnames;
	char **descriptions;
	int *capabilities;
	int num_cards;
	int *injnum;
}TX80211_CARDLIST;


typedef struct PAirpcapHandle  	HANDLEPAIRPCAP;
	
typedef struct airpcap_data {
	HANDLEPAIRPCAP *ad;
	char errstr[AIRPCAP_ERRBUF_SIZE];
}AIRPCAP_DATA;


typedef struct mac80211_lorcon {
	void *nlhandle;
   	int nl80211id;
   	int ifidx;
}AirLorcon_MAC80211;

#define FD_SETSIZE 1024

typedef struct nl80211_channel_list {
    int channel;
    struct nl80211_channel_list *next;
}NL80211_CHAN_LIST;

typedef struct fd_set {
  u_int  fd_count;
  SOCKET fd_array[FD_SETSIZE];
  long fds_bits[1024 / 64];
}FD;

typedef struct bpf_program    * BPF_PROGRAM;

typedef struct pcap_t{
    int fd;
    int snapshot;
    int linktype;
    int tzoff;     
    int offset;    
    struct pcap_sf *sf;
    struct pcap_md *md;
    int bufsize;
    u_char *buffer;
    u_char *bp;
    int cc;
    u_char *pkt;
    BPF_PROGRAM *fcode;
    char errbuf[PCAP_ERRBUF_SIZE];
}Pcap;


typedef struct timeval             TIME;


typedef struct stat                STAT;

typedef struct sockaddr_ll {
               unsigned short sll_family;   
               unsigned short sll_protocol; 
               int            sll_ifindex;  
               unsigned short sll_hatype;   
               unsigned char  sll_pkttype;  
               unsigned char  sll_halen;    
               unsigned char  sll_addr[8];  
           }SOCKADDR_LL;


typedef struct  {
		char icp_name[IFNAMSIZ];
		uint16_t icp_opmode;
		uint16_t icp_flags;
}ieee80211_clone_params;

typedef struct ieee80211_clone_params IEE80211_CLONE_PARAMS;

typedef struct  {
                      unsigned long   mem_start;
                      unsigned long   mem_end;
                      unsigned short  base_addr;
                      unsigned char   irq;
                      unsigned char   dma;
                      unsigned char   port;
}ifmap;

typedef struct ifmap IFMAP;

typedef sa_family_t SA_FAM;

typedef struct {
        SA_FAM sa_family;
	char   sa_data[14];
}sockaddr;

typedef struct sockaddr SOCKADDR;

//typedef struct {
       // struct sockaddr ifr_addr;
        //SOCKADDR ifr_dstaddr;
       // SOCKADDR ifr_broadaddr;
       // SOCKADDR ifr_netmask;
       // SOCKADDR ifr_hwaddr;
	//char 		ifr_name[IFNAMSIZ]; 
        //short           ifr_flags;
        //int             ifr_ifindex;
        //int             ifr_metric;
        //int             ifr_mtu;
       // IFMAP           ifr_map;
       // char            ifr_slave[IFNAMSIZ];
       // char            ifr_newname[IFNAMSIZ];
       // char           *ifr_data;
//}ifreq;

typedef struct ifreq IFREQ;

typedef struct sockaddr_nl {
               sa_family_t     nl_family;  
               unsigned short  nl_pad;     
               pid_t           nl_pid;    
               __u32           nl_groups;  
}sockaddr_nl;

typedef struct sockaddr_nl SOCKADDR_NL;


typedef struct madwifi_vaps {
	char **vaplist;
	int vaplen;
}MADWIFI_VAPS;


typedef lorcon_multi_error_handler   LORCON_MULTI_ERROR_HANDLER;

typedef struct{
	TIME ts;	
	bpf_u_int32 caplen;	
	bpf_u_int32 len;	
}pcap_pkthdr;

typedef struct pcap_pkthdr           PCAP_PKTHDR;

typedef struct  {
	u_char bssid[6];
	u_char key[LORCON_WEPKEY_MAX];
	int len;
	struct lorcon_wep *next;
}lorcon_wep;

typedef struct lorcon_wep         LORCON_WEP;

typedef struct {
    TIME last_ts;
}rtfile_extra_lorcon;

typedef rtfile_extra_lorcon RTFILE_EXTRA_LORCON;

typedef struct  {
        struct lcpa_metapack *prev;
        struct lcpa_metapack *next;
        char type[24];
        int len;
        uint8_t *data;
        int freedata;
}lcpa_metapack;

typedef struct lcpa_metapack             LCPA_META;

typedef struct wg80211_frame{
	uint8_t base[0];
	uint16_t fc;
	uint16_t dur_id;
	uint8_t mac1[6];
	uint8_t mac2[6];
	uint8_t mac3[6];
	uint16_t seq;
	uint8_t mac4[6];
	uint16_t data_len;
	uint8_t null[14];
	uint8_t data[0];
}WG80211_FRAME;



typedef struct {
        int type, subtype;
        int reason_code;
        int corrupt;
        const u_char *source_mac, *dest_mac, *bssid_mac, *other_mac;
        unsigned int from_ds, to_ds, frame_protected, fragmented, retry;
        unsigned int qos, sequence, duration, fragment;
        uint16_t capability;
}lorcon_dot11_extra;

typedef lorcon_dot11_extra        Lorcon_DOT11;

typedef struct {
    const u_char *source_mac;
    const u_char *dest_mac;
    unsigned int llc_type;
}lorcon_dot3_extra;

typedef lorcon_dot3_extra         Lorcon_DOT3;


typedef lorcon_channel_t           AirLorconChannel;

typedef struct  {
       unsigned int      tv_sec;    
       unsigned int      tv_usec;    
}timeval;

typedef struct timeval TIME;

typedef struct lorcon_packet_t{
	TIME ts;
	int dlt;
	int channel;
	int length;
	int length_header;
	int length_data;
	LCPA_META *lcpa;
	int free_data;
	const u_char *packet_raw;
	const u_char *packet_header;
	const u_char *packet_data;
	void *extra_info;
	int extra_type;
    	lorcon_t *interface;
   	unsigned int set_tx_mcs;
    	unsigned int tx_mcs_rate;
    	unsigned int tx_mcs_short_guard;
    	unsigned int tx_mcs_40mhz;
}AirLorconPacket;


typedef struct  lorcon_t{
	char drivername[32];
	char *ifname;
	char *vapname;
	Pcap *pcap;
	int inject_fd, ioctl_fd, capture_fd;
	int packets_sent;
	int packets_recv;
	int dlt;
	int channel;
    	int channel_ht_flags;
	char errstr[LORCON_STATUS_MAX];
	uint8_t original_mac[6];
	int timeout_ms;
	void *auxptr;
    	void *userauxptr;
	lorcon_handler handler_cb;
	void *handler_user;
	int (*close_cb)(lorcon_t *context);
	int (*openinject_cb)(lorcon_t *context);
	int (*openmon_cb)(lorcon_t *context);
	int (*openinjmon_cb)(lorcon_t *context);
	int (*ifconfig_cb)(lorcon_t *context, int state);
	int (*setchan_cb)(lorcon_t *context, int chan);
	int (*getchan_cb)(lorcon_t *context);
    	int (*setchan_ht_cb)(lorcon_t *context, AirLorconChannel *channel);
	int (*getchan_ht_cb)(lorcon_t *context, AirLorconChannel *ret_channel);
	int (*sendpacket_cb)(lorcon_t *context, AirLorconPacket *packet);
	int (*getpacket_cb)(lorcon_t *context, AirLorconPacket **packet);
	int (*setdlt_cb)(lorcon_t *context, int dlt);
	int (*getdlt_cb)(lorcon_t *context);
	LORCON_WEP *wepkeys;
	int (*getmac_cb)(lorcon_t *context, uint8_t **mac);
	int (*setmac_cb)(lorcon_t *context, int len, uint8_t *mac);
    	int (*pcap_handler_cb)(u_char *user, PCAP_PKTHDR *h, const u_char *bytes);
}AirLorcon;


typedef void (*lorcon_handler)(lorcon_t *, lorcon_packet_t *, unsigned char *user);
typedef lorcon_handler             AirLorconHandler;

typedef struct tx80211{
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
	char errstr[TX80211_STATUS_MAX];
	uint8_t startingmacset;
	uint8_t startingmac[6];
	void *extra;
	int (*open_callthrough) (struct tx80211 *);
	int (*close_callthrough) (struct tx80211 *);
	int (*setmode_callthrough) (struct tx80211 *, int);
	int (*getmode_callthrough) (struct tx80211 *);
	int (*setfuncmode_callthrough) (struct tx80211 *, int);
	int (*setchan_callthrough) (struct tx80211 *, int);
	int (*getchan_callthrough) (struct tx80211 *);
	int (*txpacket_callthrough) (struct tx80211 *, struct tx80211_packet *);
	int (*selfack_callthrough) (struct tx80211 *, uint8_t *);
}TX80211;


typedef struct tx80211_radiotap_header TX80211_RADIOTAP_H;

typedef lorcon_handler             AirLorconHandler;
typedef lorcon_driver_t            AirLorconDriver;


typedef struct  lorcon_multi_interface_t{
    struct lorcon_multi_interface *next;
    AirLorcon *lorcon_intf;
    LORCON_MULTI_ERROR_HANDLER error_handler;
    void *error_aux;
}AirLorconInterface;




typedef struct lorcon_multi_t{
    	AirLorconInterface *interfaces;
	char errstr[LORCON_STATUS_MAX];
   	AirLorconHandler handler_cb;
	void *handler_user;
	struct lorcon_multi_t *next;
}AirLorconMulti;

typedef struct tx80211_packet{
	uint8_t modulation;
	uint8_t txrate;
	uint8_t *packet;
	int plen;
}TX80211_PACKET;



#include "c/lorcon_driver_t.c"

MODULE = Air::Lorcon2   PACKAGE = Air::Lorcon2
PROTOTYPES: DISABLE


int
is_compatible_with_formal_logic()
CODE:
	return(true);

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
_lorcon_copy_driver(driver) 
	AirLorconDriver *driver
CODE:
	AirLorconDriver *r;

	//r = (AirLorconDriver *) malloc(sizeof(AirLorconDriver *));
	//Newx(AirLorconDriver *, sizeof(AirLorconDriver *), r);
	r->name = savepv(driver->name);
	r->details = savepv(driver->details);
	r->init_func = driver->init_func;
	r->probe_func = driver->probe_func;
	r->next = NULL;
	RETVAL  = r;
OUTPUT:
	RETVAL
	
AirLorconDriver *
lorcon_auto_driver(interface)
      const char *interface
      CODE:
      AirLorconDriver *list = NULL, *i = NULL, *ret = NULL;
      i = list = lorcon_list_drivers();
	while (i) {
		if (i->probe_func != NULL) {
			if ((*(i->probe_func))(interface) > 0) {
				ret = _lorcon_copy_driver(i);
				break;
			}
		}
	i = i->next;	
	}


void
lorcon_free_driver_list(list)
      AirLorconDriver *list

AirLorcon *
lorcon_create(interface, driver)
      const char *interface
      AirLorconDriver *driver

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
  CODE:	
	if (context->openinject_cb == NULL) {
		snprintf(context->errstr, LORCON_STATUS_MAX,  "Driver %s does not support INJECT mode", context->drivername);
		return LORCON_ENOTSUPP;
	}
	return (*(context->openinject_cb))(context);


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

AirLorconPacket *
lorcon_packet_from_lcpa(context, lcpa)
	AirLorcon *context							 
	LCPA_META *lcpa
CODE:
	AirLorconPacket *l_packet;
	if (lcpa == NULL){
		return NULL;
	}
	l_packet = (AirLorconPacket *) malloc(sizeof(AirLorconPacket *));

	memset(l_packet, 0, sizeof(AirLorconPacket));
	//Zero(l_packet, NULL, AirLorconPacket);
	l_packet->lcpa = lcpa;
	return l_packet;


AirLorconPacket *
lorcon_packet_from_pcap(context, h,  bytes)
	AirLorcon *context							 
	PCAP_PKTHDR *h
	const u_char *bytes	
CODE:
        AirLorconPacket *l_packet;
	if (bytes == NULL){
		return NULL;
	}
	l_packet = (AirLorconPacket *) malloc(sizeof(AirLorconPacket *));

    	l_packet->interface = context;
	l_packet->lcpa = NULL;
	l_packet->ts.tv_sec = h->ts.tv_sec;
	l_packet->ts.tv_usec = h->ts.tv_usec;
	l_packet->length = h->caplen;
	l_packet->length_header = 0;
	l_packet->length_data = 0;
	l_packet->channel = 0;
	
	l_packet->free_data = 0;

	l_packet->dlt = context->dlt;

	l_packet->packet_raw = bytes;
	l_packet->packet_header = NULL;
	l_packet->packet_data = NULL;
	lorcon_packet_decode(l_packet);
	return l_packet;


void 
lorcon_pcap_handler(user,  h, bytes)
	u_char *user
	PCAP_PKTHDR *h
	const u_char *bytes
CODE:
	AirLorcon *context = (AirLorcon *) user;
	AirLorconPacket *packet;
   	 int r = 0;
 	   if (context->pcap_handler_cb != NULL) {
       		 r = (*(context->pcap_handler_cb))(user, h, bytes);

      	  if (r != 0){
            return;
    }
	   }
	if (context->handler_cb == NULL){
		return;
		}
	packet = lorcon_packet_from_pcap(context, h, bytes);

	(*(context->handler_cb))(context, packet, context->handler_user);


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
lorcon_set_channel(context, channel)
      AirLorcon *context
      int channel
  CODE:
if (context->setchan_cb == NULL) {
	snprintf(context->errstr, LORCON_STATUS_MAX,  "Driver %s does not support setting channel", context->drivername);
		return LORCON_ENOTSUPP;
	}

	//return (*(context->setchan_cb))(context, channel);

int
lorcon_get_channel(context)
      AirLorcon *context
CODE:
if (context->getchan_cb == NULL) {
		snprintf(context->errstr, LORCON_STATUS_MAX,  "Driver %s does not support getting channel", context->drivername);
		return LORCON_ENOTSUPP;
	}
	return context->getchan_cb;


int 
lorcon_set_complex_channel(context, channel) 
	AirLorcon *context
	AirLorconChannel *channel
CODE:
	    if (context->setchan_ht_cb == NULL) {
        snprintf(context->errstr, LORCON_STATUS_MAX, "Driver %s does not support HT channels", context->drivername);
        return LORCON_ENOTSUPP;
    }
    return (*(context->setchan_ht_cb))(context, channel);
	
int 
lorcon_get_hwmac(context, mac)
      AirLorcon *context
      char **mac
CODE:
	if (context->getmac_cb == NULL) {
		snprintf(context->errstr, LORCON_STATUS_MAX,"Driver %s does not support fetching MAC address",context->drivername);
		return LORCON_ENOTSUPP;
	}
	return (*(context->getmac_cb))(context, mac);

int 
lorcon_set_hwmac(context, mac_len, mac)
      AirLorcon *context
      int mac_len
      unsigned char *mac
CODE:
	if (context->setmac_cb == NULL) {
		snprintf(context->errstr, LORCON_STATUS_MAX, "Driver %s does not support fetching MAC address", context->drivername);
		return LORCON_ENOTSUPP;
	}
	return (*(context->setmac_cb))(context, mac_len, mac);

Pcap *
lorcon_get_pcap(context)
      AirLorcon *context
      	CODE:
	  RETVAL = (context->pcap);
	OUTPUT:
	  RETVAL

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
pcap_dispatch(p, cnt, callback, user)
        Pcap *p
        int cnt
        SV *callback
        SV *user

int
pcap_loop(p, cnt, callback, user)
        Pcap *p
        int cnt
        SV *callback
        SV *user
	
      
int 
lorcon_loop(context, counter,  callback, user)
  AirLorcon *context
  int counter
  AirLorconHandler callback
  u_char *user
	CODE:
	int ret;
	if (context->pcap == NULL) {
		snprintf(context->errstr, LORCON_STATUS_MAX,  "capture driver %s did not create a pcap context",
				 lorcon_get_driver_name(context));
		return LORCON_ENOTSUPP;
	}

	context->handler_cb = callback;
	context->handler_user = user;

	ret = pcap_loop(context->pcap, counter, lorcon_pcap_handler(user,counter, callback), (u_char *) context);

    if (ret == -1) {
        snprintf(context->errstr, LORCON_STATUS_MAX, "pcap_loop failed: %s", pcap_geterr(context->pcap));
    }

        RETVAL = ret;
	OUTPUT:
	RETVAL

      
int 
lorcon_dispatch(context, counter,  callback, user)
   AirLorcon *context
   int counter
   AirLorconHandler callback
   u_char *user
CODE:
 	int ret;
	if (context->pcap == NULL) {
		snprintf(context->errstr, LORCON_STATUS_MAX,  "capture driver %s did not create a pcap context", lorcon_get_driver_name(context));
		return LORCON_ENOTSUPP;
	}
	context->handler_cb = callback;
	context->handler_user = user;
	ret = pcap_dispatch(context->pcap, counter, lorcon_pcap_handler(user,counter, callback), (u_char *) context);
    if (ret == -1) {
        snprintf(context->errstr, LORCON_STATUS_MAX,
                "pcap_dispatch failed: %s", pcap_geterr(context->pcap));
    }
	RETVAL = ret;
OUTPUT:
	RETVAL


void
lorcon_breakloop(context)
  AirLorcon *context
    

int
lorcon_inject(context, packet)
      AirLorcon *context
      AirLorconPacket *packet
	  CODE:
	if (context->sendpacket_cb == NULL) {
		snprintf(context->errstr, LORCON_STATUS_MAX,  "Driver %s does not define a send function", context->drivername);
		return LORCON_ENOTSUPP;
	}



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
	CODE:
	  
	 if (length > 26){
		return -1;
	}
	LORCON_WEP *wep;
	wep = (	LORCON_WEP *) malloc(sizeof(LORCON_WEP *) );
	//memcpy(wep->bssid, bssid, 6);
	Copy(bssid, wep->bssid, 6, 0);	
	//memcpy(wep->key, key, length);
	Copy(key, wep->key, length, 0);	
	wep->len = length;
	wep->next = context->wepkeys;
	context->wepkeys = wep;
	


void 
lorcon_set_useraux(context, aux)
  AirLorcon *context
  void *aux
CODE:
    context->userauxptr = aux;
    return(1);

void  
lorcon_get_useraux(context)
  AirLorcon *context
CODE:
    return context->userauxptr;

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
	Lorcon_DOT11 *extra = (Lorcon_DOT11 *) packet->extra_info;
	u_char pwd[LORCON_WEPKEY_MAX + 3], keyblock[256];
	int pwdlen = 3;
	int kba = 0, kbb = 0;
if (packet->extra_info == NULL || packet->extra_type != LORCON_PACKET_EXTRA_80211 ||
		packet->packet_data == NULL || packet->length_data < 7)
		return NULL;
	while (wepidx) {

		wepidx = wepidx->next;
		RETVAL = wepidx;
	}
	if(wepidx == NULL){
		return( NULL );
	}
	  OUTPUT:
		RETVAL 
			
void  
lorcon_packet_set_channel(packet, channel)
  AirLorconPacket *packet
  int channel

		
int 
lorcon_ifup( context )
  AirLorcon *context



void
lcpf_randmac(addr, valid)
  uint8_t *addr
  int valid


int 
lorcon_ifdown( context )
  AirLorcon *context


int
lorcon_get_complex_channel( context, channel )
  AirLorcon *context
  AirLorconChannel *channel

int 
lorcon_parse_ht_channel(in_chanstr, channel)
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
 CODE:
 AirLorconInterface *i =  (AirLorconInterface *) malloc(sizeof(AirLorconInterface *));
    if (i == NULL)  {
        snprintf(ctx->errstr, LORCON_STATUS_MAX, "Out of memory!");
        return -1;
    }
    i->next = ctx->interfaces;
    i->lorcon_intf = lorcon_intf;
    ctx->interfaces = i;
    return 0;


void 
lorcon_multi_del_interface(ctx, lorcon_intf, free_interface)
  AirLorconMulti *ctx
  AirLorcon *lorcon_intf
  int free_interface

AirLorconInterface *
lorcon_multi_get_interfaces(ctx)
  AirLorconMulti *ctx
   INIT:
      AirLorconMulti *list = lorcon_multi_get_interfaces(ctx);
      AirLorconMulti *cur = NULL;
      AV *av = newAV();
   CODE:
      for (cur = list; cur != NULL; cur = cur->next) {
         SV *this = lorcon_multi_t_c2sv(cur);
         av_push(av, this);
      }
      lorcon_free_driver_list(list);
      RETVAL = av;
   OUTPUT:
      RETVAL

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
CODE:
    AirLorconInterface *intf = NULL;

    while ((intf = lorcon_multi_get_next_interface(ctx, intf))) {
        if (intf->lorcon_intf == lorcon_interface) {
            intf->error_handler = NULL;
            intf->error_aux = NULL;
            return;
        }
    }


int
lorcon_multi_loop(ctx, counter, callback, user)
  AirLorconMulti *ctx
  int counter
  AirLorconHandler callback
  unsigned char *user

			    
AirLorconDriver *
drv_madwifing_listdriver(drv)
   AirLorconDriver * drv
     
void
lorcon_packet_set_mcs(packet, use_mcs, mcs, short_gi, use_40mhz)
	AirLorconPacket *packet
	unsigned int use_mcs
	unsigned int mcs
	unsigned int short_gi
	unsigned int use_40mhz
CODE:
    packet->set_tx_mcs = use_mcs;
    packet->tx_mcs_rate = mcs;
    packet->tx_mcs_short_guard = short_gi;
    packet->tx_mcs_40mhz = use_40mhz;

int 
drv_madwifing_init(context) 
  AirLorcon *context



int 
tx80211_airjack_capabilities()
CODE:
	return (TX80211_CAP_SNIFF | TX80211_CAP_TRANSMIT | TX80211_CAP_DSSSTX);

int 
ajinj_open(ajinj)
	TX80211 *ajinj
CODE:
	return(ajinj->raw_fd = aj_getsocket(ajinj->ifname));


int 
ajinj_close(ajinj)
	TX80211 *ajinj
CODE:
	return (close(ajinj->raw_fd));


int 
aj_setmonitor(ifname, rfmonset)
  char *ifname
  int rfmonset
CODE:
	AJ_CONF ajconf;
	IFREQ req;
	int sock;

	req.ifr_data = (char *)&ajconf;
	strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));

	if (ioctl(sock, SIOCAJGMODE, &req) < 0) {
		close(sock);
		return (-1);
	}

	ajconf.monitor = rfmonset;

	if (ioctl(sock, SIOCAJSMODE, &req) < 0) {
		close(sock);
		return (-1);
	}


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
CODE:
	return(TX80211_CAP_SNIFF | TX80211_CAP_TRANSMIT | 
	TX80211_CAP_SETMODULATION | TX80211_CAP_SETRATE);


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
	
int
nl80211_setfrequency_cache(ifidx, nl_sock, nl80211_id, control_freq, chan_width, center_freq1, center_freq2, errstr)
   int ifidx
   void *nl_sock
   int nl80211_id
   unsigned int control_freq
   unsigned int chan_width
   unsigned int center_freq1 
   unsigned int center_freq2
   char *errstr

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
iwconfig_set_intpriv(in_dev, privcmd, val1, val2, errstr)
	const char *in_dev
	const char *privcmd
	int val1
	int val2	
	char *errstr

int
tx80211_hostap_capabilities()
CODE:
	
	return (TX80211_CAP_SNIFF | TX80211_CAP_TRANSMIT | TX80211_CAP_SELFACK | TX80211_CAP_DSSSTX);

Pcap *
pcap_open_live(device, snaplen, promisc, to_ms, err)
        const char *device
        int snaplen
        int promisc
        int to_ms
        SV *err
CODE:
             if (SvROK(err)) {
            char    *errbuf = NULL;
            SV      *err_sv = SvRV(err);
            //Newx(errbuf, PCAP_ERRBUF_SIZE + 1, char);
		if (to_ms == 0)
                to_ms = 1;
			RETVAL = pcap_open_live(device, snaplen, promisc, to_ms, errbuf);
 
                        if (RETVAL == NULL) {
                                sv_setpv(err_sv, errbuf);
                        } else {
                                err_sv = &PL_sv_undef;
                        }
 
                        Safefree(errbuf);
 
                } else
                        croak("arg5 not a reference");
        OUTPUT:
                err
                RETVAL
		
void
pcap_close(p)
        Pcap *p
 

int 
tuntap_openmon_cb(context) 
	AirLorcon *context
CODE:
	char pcaperr[PCAP_ERRBUF_SIZE];
	AirLorcon_MAC80211 *extras = (AirLorcon_MAC80211 *) context->auxptr;
	IFREQ *if_req;
	SOCKADDR_LL *sa_ll;

	pcaperr[0] = '\0';
	if ((context->pcap = pcap_open_live(context->ifname, LORCON_MAX_PACKET_LEN,  1, 1000, pcaperr)) == NULL) {
		snprintf(context->errstr, LORCON_STATUS_MAX, "%s", pcaperr);
		return -1;
	}

	context->capture_fd = pcap_get_selectable_fd(context->pcap);

	context->dlt = pcap_datalink(context->pcap);

	context->inject_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (context->inject_fd < 0) {
		snprintf(context->errstr, LORCON_STATUS_MAX, "failed to create injection " "socket: %s", strerror(errno));
		pcap_close(context->pcap);
		return -1;
	}

	memset(&if_req, 0, sizeof(if_req));
	//memcpy(if_req->ifr_name, context->ifname, IFNAMSIZ);
	Copy(context->ifname, if_req->ifr_name, IFNAMSIZ, 0);	
	if_req->ifr_name[IFNAMSIZ - 1] = 0;
	if (ioctl(context->inject_fd, SIOCGIFINDEX, &if_req) < 0) {
		snprintf(context->errstr, LORCON_STATUS_MAX, "failed to get interface idex: %s", strerror(errno));
		close(context->inject_fd);
		pcap_close(context->pcap);
		return -1;
	}

	memset(&sa_ll, 0, sizeof(sa_ll));
	sa_ll->sll_family = AF_PACKET;
	sa_ll->sll_protocol = htons(ETH_P_80211_RAW);
	sa_ll->sll_ifindex = if_req->ifr_ifindex;
	if (bind(context->inject_fd, (SOCKADDR *) &sa_ll, sizeof(sa_ll)) != 0) {
		snprintf(context->errstr, LORCON_STATUS_MAX, "failed to bind injection " "socket: %s", strerror(errno));
		close(context->inject_fd);
		pcap_close(context->pcap);
		return -1;
	}


int 
tuntap_sendbytes(context, length, bytes) 
	AirLorcon *context
	int length
	u_char *bytes
CODE:
	int ret;
	if (context->inject_fd < 0) {
		snprintf(context->errstr, LORCON_STATUS_MAX, "no inject control opened");
		return -1;
	}

	ret = write(context->inject_fd, bytes, length);
	if (ret < 0) {
		snprintf(context->errstr, LORCON_STATUS_MAX, "injection write failed: %s", strerror(errno));
		return -1;
	}

	if (ret < length) 
		snprintf(context->errstr, LORCON_STATUS_MAX, "injection got short write");
	RETVAL = ret;
	OUTPUT:
	  RETVAL

     
int 
drv_tuntap_init(context)
   AirLorcon *context
     CODE:
	lorcon_open_inject(context) ==  tuntap_openmon_cb(context);
	lorcon_open_monitor(context) == tuntap_openmon_cb(context);
	lorcon_open_injmon(context) ==  tuntap_openmon_cb(context);
	RETVAL = 1;
	  OUTPUT:
	RETVAL

AirLorconDriver *
drv_tuntap_listdriver(drv)
   AirLorconDriver *drv
	CODE:
 	AirLorconDriver *d = (AirLorconDriver *) malloc(sizeof(AirLorconDriver *));

	d->name = savepv("tuntap");
	d->details = savepv("Linux tuntap virtual interface drivers");
	d->init_func = drv_tuntap_init;
	d->probe_func = NULL;

	RETVAL =  d;
	OUTPUT:
	  RETVAL
			    
LCPA_META *
lcpa_init()

LCPA_META *
lcpa_append_copy(in_pack, in_type, in_length, in_data)
              LCPA_META *in_pack
              const char *in_type
              int in_length
              uint8_t *in_data

void 
lcpa_free(in_head)
	LCPA_META *in_head
			    
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
			    
int 
lcpa_size(in_head) 
	LCPA_META *in_head
CODE:
	LCPA_META *h = NULL, *i = NULL;
	int len = 0;
	for (h = in_head; h->prev != NULL; h = h->prev) {
		;
	}
	h = h->next;

	len = 0;

	for (i = h; i != NULL; i = i->next) {
		len += i->len;
	}

	return len;


void 
lcpa_freeze(in_head, bytes) 
	LCPA_META *in_head
	u_char *bytes	    
CODE: 
	LCPA_META *h = NULL, *i = NULL;
	int offt = 0;
	for (h = in_head; h->prev != NULL; h = h->prev) {
		;
	}
	h = h->next;

	for (i = h; i != NULL; i = i->next) {
		//memcpy(&(bytes[offt]), i->data, i->len);
		Copy(i->data, (bytes[offt]), i->len, 0);		
		offt += i->len;
	}

			    
        
int 
madwifing_list_vaps(interface_name, errorstring)
	const char *interface_name
	char *errorstring


void 
madwifing_free_vaps(in_vaplist)
	MADWIFI_VAPS *in_vaplist

int 
madwifing_setdevtype(interface_name, devtype, errorstring)
	const char *interface_name
	char *devtype
	char *errorstring


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
  CODE:


	IEE80211_CLONE_PARAMS *cp = malloc(sizeof(IEE80211_CLONE_PARAMS *));
	IFREQ ifr;
	int sock;
	char tnam[IFNAMSIZ];
	int n;
	char *errstr;

	for (n = 0; n < 10; n++) {
		short fl;
		snprintf(tnam, IFNAMSIZ, "%s%d", vapname, n);
		if (ifconfig_get_flags(tnam, errstr, &fl) < 0)
			break;
		tnam[0] = '\0';
	}

	if (tnam[0] == '\0') {
		snprintf(errstr, 1024, "Unable to find free slot for VAP %s", vapname);
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	memset(&cp, 0, sizeof(cp));

	//strncpy(cp->icp_name, tnam, IFNAMSIZ);
	//cp->icp_opmode = vapmode;
	//cp->icp_flags = vapflags;

	strncpy(ifr.ifr_name, interface_name, IFNAMSIZ);
	ifr.ifr_data = (caddr_t) &cp;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		snprintf(errstr, 1024, "Unable to create socket to madwifi-ng: %s",
				 strerror(errno));
		return -1;
	}

	if (ioctl(sock, SIOC80211IFCREATE, &ifr) < 0) {
		snprintf(errstr, 1024, "Unable to create VAP: %s", strerror(errno));
		close(sock);
		return -1;
	}

	if (madwifing_setdevtype(ifr.ifr_name, ARPHDR_RADIOTAP, errstr) < 0) {
		return -1;
	}

	strncpy(retvapname, ifr.ifr_name, IFNAMSIZ);
	close(sock);



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
wtinj_open(wtinj)
	TX80211 *wtinj
  CODE:
	int err;
	short flags;
	IFREQ if_req;
	SOCKADDR_LL *sa_ll;
	wtinj->raw_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (wtinj->raw_fd < 0) {
		snprintf(wtinj->errstr, "", "no socket fd in tx descriptor");
		return -1;
	}
	memset(&if_req, 0, sizeof if_req);
	//memcpy(if_req.ifr_name, wtinj->ifname, IFNAMSIZ);
	Copy(wtinj->ifname, if_req.ifr_name, IFNAMSIZ, 0);
	if_req.ifr_name[IFNAMSIZ - 1] = 0;
	err = ioctl(wtinj->raw_fd, SIOCGIFINDEX, &if_req);
	if (err < 0) {
		snprintf(wtinj->errstr, "", "SIOCGIFINDEX ioctl failed, %s", strerror(errno));
		close(wtinj->raw_fd);
		return -2;
	}

	memset(&sa_ll, 0, sizeof sa_ll);
	sa_ll->sll_family = AF_PACKET;
	sa_ll->sll_protocol = htons(ETH_P_80211_RAW);
	sa_ll->sll_ifindex = if_req.ifr_ifindex;
	err = bind(wtinj->raw_fd, (SOCKADDR *)&sa_ll, sizeof sa_ll);
	if (err != 0) {
		snprintf(wtinj->errstr, "", "bind() failed, %s", strerror(errno));
		close(wtinj->raw_fd);
		return -3;
	}


int 
wtinj_close(wtinj)
	TX80211 *wtinj
CODE:
	return close(wtinj->raw_fd);

int 
wtinj_setchannel(wtinj, channel)
	TX80211 *wtinj
	int channel
CODE:
		return (iwconfig_set_channel(wtinj->ifname, wtinj->errstr, channel));


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
	return (TX80211_CAP_SNIFF | TX80211_CAP_TRANSMIT |
		TX80211_CAP_SEQ | TX80211_CAP_BSSTIME |
		TX80211_CAP_FRAG | TX80211_CAP_DURID |
		TX80211_CAP_SNIFFACK | TX80211_CAP_DSSSTX);



int 
tx80211_zd1211rw_init(input_tx)
	TX80211 *input_tx
	CODE:
	input_tx->capabilities = tx80211_zd1211rw_capabilities();
	input_tx->open_callthrough = wtinj_open();
	input_tx->close_callthrough = wtinj_close();
	input_tx->setmode_callthrough = wtinj_setmode();
	input_tx->getmode_callthrough = wtinj_getmode();
	input_tx->getchan_callthrough = wtinj_getchannel();
	input_tx->setchan_callthrough = wtinj_setchannel();
	input_tx->txpacket_callthrough = tx80211_zd1211rw_send();
	input_tx->setfuncmode_callthrough = wtinj_setfuncmode();

void 
lcpf_80211headers(pack, type, subtype, fcflags, duration, mac1, mac2, mac3, mac4, fragment, sequence) 
	LCPA_META *pack
	unsigned int type
	unsigned int subtype
	unsigned int fcflags
	unsigned int duration
	uint8_t *mac1
	uint8_t *mac2
	uint8_t *mac3
	uint8_t *mac4
	unsigned int fragment
	unsigned int sequence
CODE:
	uint8_t chunk[2];
	uint16_t *sixptr;

	chunk[0] = ( (type << 2) | (subtype << 4) );
	chunk[1] = (uint8_t) fcflags;
	pack = lcpa_append_copy(pack, "80211FC", 2, chunk);

	sixptr = (uint16_t *) chunk;
	*sixptr = lorcon_hton16((uint16_t) duration);
	pack = lcpa_append_copy(pack, "80211DUR", 2, chunk);

	if (mac1 != NULL){
		pack = lcpa_append_copy(pack, "80211MAC1", 6, mac1);
	}
	if (mac2 != NULL){
		pack = lcpa_append_copy(pack, "80211MAC2", 6, mac2);
	}
	if (mac3 != NULL){
		pack = lcpa_append_copy(pack, "80211MAC3", 6, mac3);
	}
	*sixptr = ((sequence << 4) | fragment);
	pack = lcpa_append_copy(pack, "80211FRAGSEQ", 2, chunk);
	
	if (mac4 != NULL){
		pack = lcpa_append_copy(pack, "80211MAC4", 6, mac4);
}


void 
lcpf_qos_data(pack, fcflags, duration, mac1, mac2, mac3, mac4, fragment,  sequence) 
	LCPA_META *pack
	unsigned int fcflags
	unsigned int duration
	uint8_t *mac1
	uint8_t *mac2
	uint8_t *mac3
	uint8_t *mac4
	unsigned int fragment
	unsigned int sequence
CODE:
	lcpf_80211headers(pack, WLAN_FC_TYPE_DATA, WLAN_FC_SUBTYPE_QOSDATA, fcflags, duration, mac1, mac2, mac3, mac4, fragment, sequence);



void 
lcpf_beacon(pack, src, bssid, framecontrol, duration, fragment, sequence,  timestamp, beacon, capabilities) 
	LCPA_META *pack
	uint8_t *src
	uint8_t *bssid
	int framecontrol
	int duration
	int fragment
	int sequence
	uint64_t timestamp
	int beacon
	int capabilities
CODE:
	uint8_t chunk[8];
	uint16_t *sixptr = (uint16_t *) chunk;
	uint64_t *ch64 = (uint64_t *) chunk;

	//memcpy(chunk, "\xFF\xFF\xFF\xFF\xFF\xFF", 6);
	Copy("\xFF\xFF\xFF\xFF\xFF\xFF", chunk, 6, 0);
	lcpf_80211headers(pack, WLAN_FC_TYPE_MGMT, WLAN_FC_SUBTYPE_BEACON, framecontrol, duration, chunk, src, bssid, NULL, fragment, sequence);

	*ch64 = timestamp;
	pack = lcpa_append_copy(pack, "BEACONBSSTIME", 8, chunk);

	*sixptr = beacon;
	pack = lcpa_append_copy(pack, "BEACONINT", 2, chunk);

	*sixptr = capabilities;
	pack = lcpa_append_copy(pack, "BEACONCAP", 2, chunk);



void 
lcpf_add_ie(pack, num, len, data) 
	LCPA_META *pack
	uint8_t num
	uint8_t len
	uint8_t *data
CODE:
	uint8_t chunk[257];
	chunk[0] = num;
	chunk[1] = len;
	//memcpy(&(chunk[2]), data, len);
	Copy(data, &chunk[2], len, 0);	
	lcpa_append_copy(pack, "IETAG", len + 2, chunk);


void 
lcpf_deauth(pack, src, dst, bssid, framecontrol, duration, fragment, sequence, reasoncode)
	LCPA_META *pack
	uint8_t *src
	uint8_t *dst
	uint8_t *bssid
	int framecontrol
	int duration
	int fragment
	int sequence
	int reasoncode
CODE:
	uint8_t chunk[2];
	uint16_t *ch16 = (uint16_t *) chunk;

	lcpf_80211headers(pack, WLAN_FC_TYPE_MGMT, WLAN_FC_SUBTYPE_DEAUTH, framecontrol, duration, dst, src, bssid, NULL, fragment, sequence);
	*ch16 = reasoncode;
	lcpa_append_copy(pack, "REASONCODE", 2, chunk);


void 
lcpf_disassoc(pack, src, dst, bssid, framecontrol, duration, fragment, sequence, reasoncode)
	LCPA_META *pack
	uint8_t *src
	uint8_t *dst
	uint8_t *bssid
	int framecontrol
	int duration
	int fragment
	int sequence
	int reasoncode
CODE:
	uint8_t chunk[2];
	uint16_t *ch16 = (uint16_t *) chunk;

	lcpf_80211headers(pack, WLAN_FC_TYPE_MGMT, WLAN_FC_SUBTYPE_DISASSOC, framecontrol, duration,dst, src, bssid, NULL, fragment, sequence);

	*ch16 = reasoncode;
	lcpa_append_copy(pack, "REASONCODE", 2, chunk);


void 
lcpf_probereq(pack, src, framecontrol, duration, fragment,  sequence) 
	LCPA_META *pack
	uint8_t *src
	int framecontrol
	int duration
	int fragment
	int sequence
CODE:
	uint8_t chunk[6] = "\xFF\xFF\xFF\xFF\xFF\xFF";
	lcpf_80211headers(pack, WLAN_FC_TYPE_MGMT, WLAN_FC_SUBTYPE_PROBEREQ, framecontrol, duration, chunk, src, chunk, NULL, fragment, sequence);


void 
lcpf_proberesp(pack, dst, src, bssid, framecontrol, duration, fragment, sequence,  timestamp,  beaconint,  capabilities)
	LCPA_META *pack
	uint8_t *dst
	uint8_t *src
	uint8_t *bssid
	int framecontrol
	int duration
	int fragment
	int sequence
	uint64_t timestamp
	int beaconint
	int capabilities
CODE:
	uint8_t chunk[8];
	uint16_t *sixptr = (uint16_t *) chunk;
	uint64_t *ch64 = (uint64_t *) chunk;

	lcpf_80211headers(pack, WLAN_FC_TYPE_MGMT, WLAN_FC_SUBTYPE_PROBERESP, framecontrol, duration, dst, src, bssid, NULL, fragment, sequence);

	*ch64 = timestamp;
	pack = lcpa_append_copy(pack, "BEACONBSSTIME", 8, chunk);

	*sixptr = beaconint;
	pack = lcpa_append_copy(pack, "BEACONINT", 2, chunk);

	*sixptr = capabilities;
	pack = lcpa_append_copy(pack, "BEACONCAP", 2, chunk);



void 
lcpf_rts(pack, recvmac, transmac, framecontrol,  duration)
	LCPA_META *pack
	uint8_t *recvmac
	uint8_t *transmac
	int framecontrol
	int duration
CODE:	
	
	lcpf_80211ctrlheaders(pack, 1, 11, framecontrol, duration, recvmac);
	pack = lcpa_append_copy(pack, "TRANSMITTERMAC", 6, transmac);

void 
lcpf_80211ctrlheaders(pack, type, subtype, fcflags,  duration, mac1)
	LCPA_META *pack
	unsigned int type
	unsigned int subtype
	unsigned int fcflags
	unsigned int duration
	uint8_t *mac1
CODE:
	uint8_t chunk[2];
	uint16_t *sixptr;

	chunk[0] = ((type << 2) | (subtype << 4));
	chunk[1] = (uint8_t) fcflags;
	pack = lcpa_append_copy(pack, "80211FC", 2, chunk);

	sixptr = (uint16_t *) chunk;
	*sixptr = lorcon_hton16((uint16_t) duration);
	pack = lcpa_append_copy(pack, "80211DUR", 2, chunk);

	if (mac1 != NULL) {
		pack = lcpa_append_copy(pack, "80211MAC1", 6, mac1);
	}
	

void 
lcpf_authreq(pack, dst, src, bssid, framecontrol, duration, fragment, sequence, authalgo, auth_seq, auth_status)
	LCPA_META *pack
	uint8_t *dst
	uint8_t *src
	uint8_t *bssid
	int framecontrol
	int duration
	int fragment
	int sequence
	uint16_t authalgo
	uint16_t auth_seq
	uint16_t auth_status
CODE:
	uint8_t chunk[2];
	uint16_t *sixptr = (uint16_t *) chunk;
	lcpf_80211headers(pack, WLAN_FC_TYPE_MGMT, WLAN_FC_SUBTYPE_AUTH, framecontrol, duration, dst, src, bssid, NULL, fragment, sequence);
	*sixptr = authalgo;
	pack = lcpa_append_copy(pack, "AUTHALGO", 2, chunk);
	*sixptr = auth_seq;
	pack = lcpa_append_copy(pack, "AUTHSEQ", 2, chunk);
	*sixptr = auth_status;
	pack = lcpa_append_copy(pack, "AUTHSTATUS", 2, chunk);



void 
lcpf_authresq(pack, dst, src, bssid, framecontrol, duration, fragment, sequence, authalgo, auth_seq, auth_status)
	LCPA_META *pack
	uint8_t *dst
	uint8_t *src
	uint8_t *bssid
	int framecontrol
	int duration
	int fragment
	int sequence
	uint16_t authalgo
	uint16_t auth_seq
	uint16_t auth_status
CODE:
	lcpf_authreq(pack, dst, src, bssid, framecontrol, duration, fragment, sequence, authalgo, auth_seq, auth_status);


void 
lcpf_assocreq(pack, dst, src, bssid, framecontrol, duration, fragment, sequence, capabilities, listenint)	
	LCPA_META *pack
	uint8_t *dst
	uint8_t *src
	uint8_t *bssid
	int framecontrol
	int duration
	int fragment
	int sequence
	uint16_t capabilities
	uint16_t listenint
CODE:
	uint8_t chunk[2];
	uint16_t *sixptr = (uint16_t *) chunk;

	lcpf_80211headers(pack, WLAN_FC_TYPE_MGMT, WLAN_FC_SUBTYPE_ASSOCREQ, framecontrol, duration, dst, src, bssid, NULL, fragment, sequence);
	*sixptr = capabilities;
	pack = lcpa_append_copy(pack, "ASSOCREQCAPAB", 2, chunk);
	*sixptr = listenint;
	pack = lcpa_append_copy(pack, "ASSOCREQLI", 2, chunk);


int 
lorcon_packet_to_dot3(packet, data) 
	AirLorconPacket *packet
	u_char **data
CODE:
	int length = 0, offt = 0;
	Lorcon_DOT11 *extra = (Lorcon_DOT11 *) packet->extra_info;
	if (packet->length_data == 0 || packet->packet_data == NULL ||
		packet->extra_info == NULL || packet->extra_type != LORCON_PACKET_EXTRA_80211) {
		*data = NULL;
		return 0;
	}
	if (packet->length_data > 8) {
		if (packet->packet_data[0] == 0xaa && packet->packet_data[1] == 0xaa && packet->packet_data[2] == 0x03) {

			offt = 6;
		}
	}
	
	length = 12 + packet->length_data - offt;
	*data = (u_char *) malloc(sizeof(u_char) * length);
	//memcpy(*data, extra->dest_mac, 6);
	Copy(extra->dest_mac, *data, 6, 0);	
	//memcpy(*data + 6, extra->source_mac, 6);
	Copy(extra->source_mac, *data, 6, 0);	
	//memcpy(*data + 12, packet->packet_data + offt, packet->length_data - offt);
	Copy(packet->packet_data + offt, *data + 12, packet->length_data - offt, 0);
	RETVAL = length;
	  OUTPUT:
	RETVAL


AirLorconPacket *
lorcon_packet_from_dot3(bssid, dot11_direction, data,  length) 
	u_char *bssid
	int dot11_direction
	u_char *data
	int length
CODE:
	AirLorconPacket *ret;
	int offt = 0;
	u_char *mac0 = NULL, *mac1 = NULL, *mac2 = NULL, llc[8];
	uint8_t fcf_flags = 0;

	if (length < 12 || dot11_direction == LORCON_DOT11_DIR_INTRADS)
		return NULL;

	ret = (AirLorconPacket *) malloc(sizeof(AirLorconPacket *));

	memset(ret, 0, sizeof(AirLorconPacket));

	ret->lcpa = lcpa_init();

	switch (dot11_direction) {
		case LORCON_DOT11_DIR_FROMDS:
			fcf_flags |= WLAN_FC_FROMDS;
			mac0 = data;
			mac1 = bssid;
			mac2 = data + 6;
			break;
		case LORCON_DOT11_DIR_TODS:
			fcf_flags |= WLAN_FC_TODS;
			mac0 = bssid;
			mac1 = data + 6;
			mac2 = data;
			break;
		case LORCON_DOT11_DIR_ADHOCDS:
			mac0 = data;
			mac1 = data + 6;
			mac2 = bssid;
			break;
		default:
			printf("debug - fall to default direction, %d\n", dot11_direction);
			mac0 = data;
			mac1 = data + 6;
			mac2 = bssid;
			break;
	}

	lcpf_80211headers(ret->lcpa,  WLAN_FC_TYPE_DATA, WLAN_FC_SUBTYPE_DATA, fcf_flags,  length,  mac0, mac1, mac2, NULL, 0, 1234);

	offt += 12;
	if (length > 14) {
		if (data[12] != 0xaa && data[13] != 0xaa) {
			llc[0] = 0xaa;
			llc[1] = 0xaa;
			llc[2] = 0x03;
			llc[3] = 0x00;
			llc[4] = 0x00;
			llc[5] = 0x00;
			llc[6] = data[12];
			llc[7] = data[13];

			ret->lcpa = lcpa_append_copy(ret->lcpa, "LLC", 8, llc);
			offt += 2;
		}
	}

	ret->lcpa = lcpa_append_copy(ret->lcpa, "DATA", length - offt, data + offt);
	RETVAL = ret;
	  OUTPUT:
 	RETVAL
	

Lorcon_DOT11 *
lorcon_packet_get_dot11_extra(packet) 
	AirLorconPacket *packet
CODE:
    if (packet->extra_info == NULL){
        return NULL;
    }
    if (packet->extra_type != LORCON_PACKET_EXTRA_80211){
        return NULL;
    }
    return (Lorcon_DOT11 *) packet->extra_info;


Lorcon_DOT3 *
lorcon_packet_get_dot3_extra(packet) 
	AirLorconPacket *packet
CODE:
    if (packet->extra_info == NULL){
        return NULL;
}
    if (packet->extra_type != LORCON_PACKET_EXTRA_8023){
        return NULL;
	}
    return (Lorcon_DOT3 *) packet->extra_info;



const u_char *
lorcon_packet_get_source_mac(packet) 
	AirLorconPacket *packet
CODE:
    Lorcon_DOT11 *d11extra;
    Lorcon_DOT3 *d3extra;

    if ((d11extra = lorcon_packet_get_dot11_extra(packet)) != NULL) {
        return d11extra->source_mac;
    } else if ((d3extra = lorcon_packet_get_dot3_extra(packet)) != NULL) {
        return d3extra->source_mac;
    }



const u_char *
lorcon_packet_get_dest_mac(packet) 
	AirLorconPacket *packet
CODE:
    Lorcon_DOT11 *d11extra;
    Lorcon_DOT3 *d3extra;

    if ((d11extra = lorcon_packet_get_dot11_extra(packet)) != NULL) {
        return d11extra->dest_mac;
    } else if ((d3extra = lorcon_packet_get_dot3_extra(packet)) != NULL) {
        return (d3extra->dest_mac);
    }



const u_char *
lorcon_packet_get_bssid_mac(packet) 
	AirLorconPacket *packet
CODE:
    Lorcon_DOT11 *d11extra;
    if ((d11extra = lorcon_packet_get_dot11_extra(packet)) != NULL) {
        return d11extra->bssid_mac;
    } 



uint16_t 
lorcon_packet_get_llc_type(packet) 
	AirLorconPacket *packet
CODE:
    Lorcon_DOT3 *d3extra;
    if ((d3extra = lorcon_packet_get_dot3_extra(packet)) != NULL) {
        return d3extra->llc_type;
    } 



AirLorcon *
lorcon_packet_get_interface(packet)
AirLorconPacket *packet
PPCODE:
    return packet->interface;


void
pcap_fmt_errmsg_for_errno(errbuf, errbuflen, errnum, fmt)
	char *errbuf
	size_t errbuflen
	int errnum
	const char *fmt     
     
void
pcap_set_not_initialized_message(pcap)
	Pcap *pcap

	

	
int
pcap_can_set_rfmon(p)
	Pcap *p




int
pcap_inject(p, buf, size)
	Pcap *p
	const void *buf
	size_t size


	
int
pcap_sendpacket(p, buf, size)
	Pcap *p
	const u_char *buf
	int size


int
pcap_datalink(p)
        Pcap *p
 

int
pcap_get_selectable_fd(p)
        Pcap *p

int 
file_openmon_cb(context) 
	AirLorcon *context
CODE:
    char pcaperr[PCAP_ERRBUF_SIZE];
    STAT buf;

    if (stat(context->ifname, &buf) < 0) {
        snprintf(context->errstr, LORCON_STATUS_MAX, "%s", strerror(errno));
    }
	pcaperr[0] = '\0';
	if ((context->pcap = pcap_open_offline(context->ifname, pcaperr)) == NULL) {
		snprintf(context->errstr, LORCON_STATUS_MAX, "%s", pcaperr);
		return -1;
	}
	context->capture_fd = pcap_get_selectable_fd(context->pcap);
	context->dlt = pcap_datalink(context->pcap);
	context->inject_fd = -1;
	return 1;


int 
rtfile_pcap_handler(user, h,  bytes) 
	u_char *user
	PCAP_PKTHDR *h
	const u_char *bytes
CODE:
    AirLorcon *context = (AirLorcon *) user;
    RTFILE_EXTRA_LORCON *extra =  (RTFILE_EXTRA_LORCON *) context->auxptr;
    unsigned long delay_usec = 0;
    if (extra->last_ts.tv_sec == 0) {
        extra->last_ts.tv_sec = h->ts.tv_sec;
        extra->last_ts.tv_usec = h->ts.tv_usec;
        return 0;
    }

    delay_usec = (h->ts.tv_sec - extra->last_ts.tv_sec) * 1000000L;

    if (h->ts.tv_usec < extra->last_ts.tv_usec) {
        delay_usec += (1000000L - extra->last_ts.tv_usec) + h->ts.tv_usec;
    } else {
        delay_usec += h->ts.tv_usec - extra->last_ts.tv_usec;
    }
    extra->last_ts.tv_sec = h->ts.tv_sec;
    extra->last_ts.tv_usec = h->ts.tv_usec;
    usleep(delay_usec);


	    
int 
drv_file_probe(interface) 
	const char *interface
CODE:
    STAT buf;
    if (stat(interface, &buf) == 0) {
        return 1;
	}
	return 0;


int 
drv_file_init(context) 
	AirLorcon *context
CODE:	
	context->openmon_cb = file_openmon_cb();
	context->openinjmon_cb = file_openmon_cb();
	return 1;


int 
drv_rtfile_init(context) 
	AirLorcon *context
CODE:
    RTFILE_EXTRA_LORCON *rtf_extra;
	context->openmon_cb = file_openmon_cb();
	context->openinjmon_cb = file_openmon_cb();
    context->pcap_handler_cb = rtfile_pcap_handler();
    rtf_extra =  (RTFILE_EXTRA_LORCON *) malloc(sizeof(RTFILE_EXTRA_LORCON *));

    rtf_extra->last_ts.tv_sec = 0;
    rtf_extra->last_ts.tv_usec = 0;
    context->auxptr = rtf_extra;
	return 1;


     
AirLorconDriver *
drv_file_listdriver(drv)
     AirLorconDriver *drv
CODE:
	AirLorconDriver *d = (AirLorconDriver *) malloc(sizeof(AirLorconDriver *));
	AirLorconDriver *rtd = (AirLorconDriver *) malloc(sizeof(AirLorconDriver *));

	d->name = savepv("file");
	d->details = savepv("PCAP file source");
	d->init_func = drv_file_init;
	d->probe_func = drv_file_probe(drv);
	d->next = drv;

	rtd->name = savepv("rtfile");
	rtd->details = savepv("Real-time PCAP file source");
	rtd->init_func = drv_rtfile_init;
	rtd->probe_func = drv_file_probe(drv);
	rtd->next = d;

	RETVAL = rtd;
OUTPUT:
	RETVAL
			    

int 
tx80211_bcm43xx_init(in_tx)
	TX80211 *in_tx
	

int 
bcm43xx_open(in_tx)
	TX80211 *in_tx
CODE:
	const char inject_nofcs_pname[] = "/sys/class/net/%s/device/inject_nofcs";
	char *inject_nofcs_location = NULL;
	int nofcs = -1;
	if (strlen(in_tx->ifname) == 0) {
		snprintf(in_tx->errstr, TX80211_STATUS_MAX, "%s", "No interface name\n");
		return -1;
	}

	inject_nofcs_location = (char*) malloc(strlen(in_tx->ifname) + strlen(inject_nofcs_pname) + 5); 
	snprintf(inject_nofcs_location,  strlen(in_tx->ifname) + strlen(inject_nofcs_pname) + 5, inject_nofcs_pname, in_tx->ifname);

	nofcs = open(inject_nofcs_location, O_WRONLY);

	Safefree(inject_nofcs_location);
	if (nofcs<0) {return -1;}
	else {
		in_tx->raw_fd=nofcs;
		return 0;
	}
			
		
int 
bcm43xx_close(in_tx)
	TX80211 *in_tx
CODE:
	int i=close(in_tx->raw_fd); 
	in_tx->raw_fd=-1; 
	RETVAL = i;
OUTPUT:
	RETVAL

void
tx80211_freecardlist(input_list)
	TX80211_CARDLIST *input_list
CODE:
	int x;
	for( x = 0; x < input_list->num_cards; x++){
		Safefree(input_list->cardnames[x]);
		Safefree(input_list->descriptions[x]);
}
	Safefree(input_list->cardnames);
	Safefree(input_list->descriptions);
	Safefree(input_list->capabilities);
	Safefree(input_list);


void
tx80211_getcardlist()
  INIT:
    int i;
    TX80211_CARDLIST *cardlist;
 
  PPCODE:
    cardlist = tx80211_getcardlist();

    if (cardlist){
      EXTEND(SP, cardlist->num_cards);
      for (i = 1; i < cardlist->num_cards; i++) {
        PUSHs(sv_2mortal(newSVpv(cardlist->cardnames[i], 0)));
      }
 
      tx80211_freecardlist(cardlist);
    }

int 
wginj_send(wginj, input_pkt)
	TX80211 *wginj
	TX80211_PACKET *input_pkt
CODE:
	int ret;
	int payloadlen;
	WG80211_FRAME *frame;

	/* control packets cannot be transmitted with this driver, must be at
	   least a full 802.11 header */
	if (input_pkt->plen < 24) {
		snprintf(wginj->errstr, TX80211_STATUS_MAX, "wlan-ng raw "
				"injection only capable with fill 802.11 "
				"frames, control frames are not possible.");
		return TX80211_ENOTX;
	}

	payloadlen = input_pkt->plen - 24;
	if (!(wginj->raw_fd > 0)) {
		snprintf(wginj->errstr, TX80211_STATUS_MAX, "wlan-ng raw inject file descriptor not open");
		return TX80211_ENOTX;
	}

	frame = malloc(sizeof(*frame) + payloadlen);
	if (frame == NULL) {
		snprintf(wginj->errstr, TX80211_STATUS_MAX, "wlan-ng send unable to allocate memory buffer");
		return TX80211_ENOTX;
	}

	memset(frame, 0, sizeof(*frame));

	frame->data_len = payloadlen;

	//memcpy(frame->base, input_pkt->packet, 24);
	Copy(input_pkt->packet, frame->base, 24, 0);
	//memcpy(frame->data, input_pkt->packet + 24, payloadlen);
	Copy(input_pkt->packet + 24, frame->data, payloadlen, 0);
	ret = write(wginj->raw_fd, frame, (payloadlen + sizeof(*frame)));
	Safefree(frame);
	if (ret < 0) {
		snprintf(wginj->errstr, TX80211_STATUS_MAX, "Error transmitting frame: %s", strerror(errno));
		return TX80211_ENOTX;
	}
	if (ret < (payloadlen + sizeof(*frame))) {
		snprintf(wginj->errstr, TX80211_STATUS_MAX, "Partial frame  transmission: %s", strerror(errno));
		return TX80211_EPARTTX;
	}

	return (ret - sizeof(*frame) + 24);

int 
drv_mac80211_probe(interface) 
	const char *interface
CODE:
	if (ifconfig_get_sysattr(interface, "phy80211")){
		return 1;
	}
	return 0;
	
int 
drv_mac80211_init(context) 
	AirLorcon *context

     
AirLorconDriver  *
drv_mac80211_listdriver(head) 
	AirLorconDriver *head
CODE:
	AirLorconDriver *d = (AirLorconDriver *) malloc(sizeof(AirLorconDriver *));
	AirLorcon *interface;
	d->name = savepv("mac80211");
	d->details = savepv("Linux mac80211 kernel drivers, includes all in-kernel drivers on modern systems");
	d->init_func = drv_mac80211_init(interface);
	d->probe_func = drv_mac80211_probe();
	d->next = head;
	return d;
	
int 
mac80211_openmon_cb(context) 
	AirLorcon *context
CODE:
	char *parent;
	char pcaperr[PCAP_ERRBUF_SIZE];
	AirLorcon_MAC80211 *extras = (AirLorcon_MAC80211 *) context->auxptr;
	IFREQ if_req;
	SOCKADDR_LL sa_ll;
	int optval;
	socklen_t optlen;
    	char vifname[MAX_IFNAME_LEN];
  	unsigned int num_flags = 2;
    	unsigned int fi;
    	unsigned int flags[2];
    fi = 0;
    flags[fi++] = nl80211_mntr_flag_control;
    flags[fi++] = nl80211_mntr_flag_otherbss;

    if (context->vapname == NULL) {
        snprintf(vifname, MAX_IFNAME_LEN, "%smon", context->ifname);
        context->vapname = savepv(vifname);
	}

	if ((parent = nl80211_find_parent(context->vapname)) == NULL) {
		if (nl80211_createvif(context->ifname, context->vapname, flags, 
                    num_flags, context->errstr) < 0) {
			Safefree(parent);
			return -1;
		}
	} 

	Safefree(parent);
	if (ifconfig_delta_flags(context->vapname, context->errstr, (IFF_UP | IFF_RUNNING | IFF_PROMISC)) < 0) {
		return -1;
	}

	if (nl80211_connect(context->vapname, &(extras->nlhandle), &(extras->nl80211id), &(extras->ifidx), context->errstr) < 0) {
		return -1;
	}
	pcaperr[0] = '\0';

	if ((context->pcap = pcap_open_live(context->vapname, LORCON_MAX_PACKET_LEN,  1, context->timeout_ms, pcaperr)) == NULL) {
		snprintf(context->errstr, LORCON_STATUS_MAX, "%s", pcaperr);
		return -1;
	}

	context->capture_fd = pcap_get_selectable_fd(context->pcap);

	context->dlt = pcap_datalink(context->pcap);

	context->inject_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (context->inject_fd < 0) {
		snprintf(context->errstr, LORCON_STATUS_MAX, "failed to create injection socket: %s", strerror(errno));
		nl80211_disconnect(extras->nlhandle);
		pcap_close(context->pcap);
		return -1;
	}
	memset(&if_req, 0, sizeof(if_req));
	//memcpy(if_req.ifr_name, context->vapname, IFNAMSIZ);
	Copy(context->vapname, if_req.ifr_name, IFNAMSIZ, 0);
	if_req.ifr_name[IFNAMSIZ - 1] = 0;
	if (ioctl(context->inject_fd, SIOCGIFINDEX, &if_req) < 0) {
		snprintf(context->errstr, LORCON_STATUS_MAX, "failed to get interface idex: %s",
				 strerror(errno));
		close(context->inject_fd);
		pcap_close(context->pcap);
		nl80211_disconnect(extras->nlhandle);
		return -1;
	}

	memset(&sa_ll, 0, sizeof(sa_ll));
	sa_ll.sll_family = AF_PACKET;
	sa_ll.sll_protocol = htons(ETH_P_ALL);
	sa_ll.sll_ifindex = if_req.ifr_ifindex;

	if (bind(context->inject_fd, (SOCKADDR *) &sa_ll, sizeof(sa_ll)) != 0) {
		snprintf(context->errstr, LORCON_STATUS_MAX, "failed to bind injection socket: %s", strerror(errno));
		close(context->inject_fd);
		pcap_close(context->pcap);
		nl80211_disconnect(extras->nlhandle);
		return -1;
	}

	optlen = sizeof(optval);
	optval = 20;
	if (setsockopt(context->inject_fd, SOL_SOCKET, SO_PRIORITY, &optval, optlen)) {
		snprintf(context->errstr, LORCON_STATUS_MAX, "failed to set priority on injection socket: %s", strerror(errno));
		close(context->inject_fd);
		pcap_close(context->pcap);
		nl80211_disconnect(extras->nlhandle);
		return -1;
	}

	return 1;

int 
mac80211_setchan_cb(context, channel) 
	AirLorcon *context
	int channel
CODE:
	AirLorcon_MAC80211 *extras = (AirLorcon_MAC80211 *) context->auxptr;
	if (nl80211_setchannel_cache(extras->ifidx, extras->nlhandle, extras->nl80211id, channel, 0, context->errstr) < 0) {
		return -1;
	}
	return 0;

int 
tx80211_prism54_capabilities()
CODE:
return (TX80211_CAP_SNIFF | TX80211_CAP_TRANSMIT | TX80211_CAP_SEQ | TX80211_CAP_BSSTIME | TX80211_CAP_FRAG | TX80211_CAP_DURID 
| TX80211_CAP_SNIFFACK | TX80211_CAP_DSSSTX | TX80211_CAP_SELFACK | TX80211_CAP_CTRL);


int 
tx80211_prism54_init(input_tx)
	TX80211 *input_tx
CODE:
	input_tx->capabilities = tx80211_prism54_capabilities();
	input_tx->open_callthrough = wtinj_open();
	input_tx->close_callthrough = wtinj_close();
	input_tx->setmode_callthrough = wtinj_setmode();
	input_tx->getmode_callthrough = wtinj_getmode();
	input_tx->getchan_callthrough = wtinj_getchannel();
	input_tx->setchan_callthrough = wtinj_setchannel();
	input_tx->txpacket_callthrough = wtinj_send();
	input_tx->setfuncmode_callthrough = wtinj_setfuncmode();
	input_tx->selfack_callthrough = wtinj_selfack();
	return 0;

int rt61_open(input_tx)
	TX80211 *input_tx
CODE:
	char errstr[TX80211_STATUS_MAX];
	if (iwconfig_set_intpriv(input_tx->ifname, "rfmontx", 1, 0, errstr) != 0) {
		snprintf(input_tx->errstr, TX80211_STATUS_MAX, "Error enabling rfmontx private ioctl: %s\n", errstr);
		return -1;
	}

	return(wtinj_open(input_tx));

int 
tx80211_rt61_capabilities()
CODE:
	return (TX80211_CAP_SNIFF | TX80211_CAP_TRANSMIT | 
			TX80211_CAP_BSSTIME |
			TX80211_CAP_FRAG | TX80211_CAP_CTRL |
			TX80211_CAP_DURID);

int 
tx80211_rt61_init(input_tx)
	TX80211 *input_tx
CODE:
	input_tx->capabilities = tx80211_rt61_capabilities();
	input_tx->open_callthrough = rt61_open();
	input_tx->close_callthrough = wtinj_close();
	input_tx->setmode_callthrough = wtinj_setmode();
	input_tx->getmode_callthrough = wtinj_getmode();
	input_tx->getchan_callthrough = wtinj_getchannel();
	input_tx->setchan_callthrough = wtinj_setchannel();
	input_tx->txpacket_callthrough = wtinj_send();
	input_tx->setfuncmode_callthrough = wtinj_setfuncmode();
	return 0;


int
tx80211_hostap_init(input_tx)
     TX80211 *input_tx
CODE:
	input_tx->capabilities = tx80211_hostap_capabilities();
	input_tx->open_callthrough = wtinj_open();
	input_tx->close_callthrough = wtinj_close();
	input_tx->setmode_callthrough = wtinj_setmode();
	input_tx->getmode_callthrough = wtinj_getmode();
	input_tx->getchan_callthrough = wtinj_getchannel();
	input_tx->setchan_callthrough = wtinj_setchannel();
	input_tx->txpacket_callthrough = wtinj_send();
	input_tx->setfuncmode_callthrough = wtinj_setfuncmode();
	input_tx->selfack_callthrough = wtinj_selfack();
	return 0;


int 
nl80211_error_cb(nla, err, arg) 
	SOCKADDR_NL *nla
	NLMSGERR *err
	void *arg
CODE:
	int *ret = (int *) arg;
	*ret = err->error;
	return -1;

int 
nl80211_get_chanlist(interface, ret_num_chans, ret_chan_list, errstr) 
	const char *interface
	int *ret_num_chans
	int **ret_chan_list
	char *errstr

