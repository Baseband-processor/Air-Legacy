#define INT_MAX    2147483647
#define TIMESTAMP_LEN           8
#define MAC_ADDR_LEN 		6
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

#define RADIOTAP_HEADER \
"\0\0" \

#define IEEE80211_RADIOTAP_F_FRAG	0x08
#define TX80211_CAP_CTRL	64
#define TX80211_CAP_SELFACK	512
#define SIOCDEVPRIVATE  0x89F0
#define SIOCAJSMODE SIOCDEVPRIVATE

#define XS_unpack_charPtrPtr 
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

#define DOT1X_EAP_PACKET	0x00
#define EAP_IDENTITY 		0x01
#define EAP_EXPANDED            0xFE

#define EAP_REQUEST  1
#define	EAP_RESPONSE 2
#define	EAP_SUCCESS  3
#define	EAP_FAILURE 4

#define lorcon_hton16(x) (x)

#define ETH_P_ECONET	0x0018
#define ETH_P_80211_RAW (ETH_P_ECONET + 1)
#define ARPHDR_RADIOTAP "803"


#define SIOC80211IFCREATE (SIOCDEVPRIVATE+7)

#define SHA1_DIGEST_LEN 20

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"


#include "Ctxs.h"

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef struct {
	__u32		nlmsg_len;	
	__u16		nlmsg_type;	
	__u16		nlmsg_flags;
	__u32		nlmsg_seq;	
	__u32		nlmsg_pid;	
}nlmsghdr;

typedef struct nlmsghdr NLMSGHDR;


typedef struct{
    uint32_t total[2];
    uint32_t state[5];
    uint8_t buffer[64];
}sha1_context;

typedef struct {
    sha1_context ctx;
    uint8_t k_opad[64];
}sha1_hmac_context;

typedef struct nlmsgerr {
	int	error;
	NLMSGHDR *msg;
};

typedef struct  wps_data{
	void *ap_settings_cb_ctx;
	WPS_CREDENTIAL *use_cred;
	int use_psk_key;
}WPS_DATA;

typedef struct  nlmsgerr NLMSGERR;

typedef struct {
	int 	nm_protocol;
	int 	nm_flags;
	struct sockaddr_nl *nm_src;
	struct sockaddr_nl *nm_dst;
	struct ucred *nm_creds;
	NLMSGHDR * 	nm_nlh;
	size_t 	nm_size;
	int 	nm_refcnt;
 }nl_msg;

typedef struct nl_msg NL_MSG;

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

#ifndef SOCKET
typedef unsigned int SOCKET;
#endif

typedef struct {
	union
	{
		char	ifrn_name[IFNAMSIZ];	/* if name, e.g. "eth0" */
	} ifr_ifrn;
	union	iwreq_data	u;
}iwreq;


typedef struct fd_set {
  u_int  fd_count;
  SOCKET fd_array[FD_SETSIZE];
  long fds_bits[1024 / 64];
}FD;

typedef struct bpf_program    * BPF_PROGRAM;

typedef struct pcap_opt {
	char	*device;
	int	timeout;	
	u_int	buffer_size;
	int	promisc;
	int	rfmon;	
	int	immediate;	
	int	nonblock;	
	int	tstamp_type;
	int	tstamp_precision;
#ifdef __linux__
	int	protocol;	
#endif
} PCAP_OPT;

typedef int (*can_set_rfmon_op_t)(pcap_t *);
typedef int	(*inject_op_t)(pcap_t *, const void *, int);

typedef struct pcap_t{
    int fd;
    int snapshot;
    int linktype;
    int tzoff; 
    int offset;  
    int version_major;
    int version_minor;
    int linktype_ext;
    int activated;	
    int oldstyle;
    struct pcap_sf *sf;
    struct pcap_md *md;
    int bufsize;
    u_char *buffer;
    u_char *bp;
    int cc;
    u_char *pkt;
    BPF_PROGRAM *fcode;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_opt *opt;
    inject_op_t inject_op;
    can_set_rfmon_op_t can_set_rfmon_op;
}Pcap;


typedef struct timeval             TIME;


typedef struct association_request_management_frame{
	le16 capability;
	le16 listen_interval;
}ASSOCIATION_REQUEST_MANAGEMENT_FRAME;


typedef struct association_response_management_frame{
	le16 capability;
	le16 status;
	le16 id;
}ASSOCIATION_RESP_MANAGEMENT_FRAME;

typedef struct  beacon_management_frame{
	unsigned char timestamp[TIMESTAMP_LEN];
	le16 beacon_interval;
	le16 capability;
}BEACON_MANAGEMENT_FRAME;


typedef struct {
	int proto;
	int pairwise_cipher;
	int group_cipher;
	int key_mgmt;
	int capabilities;
	size_t num_pmkid;
	const u8 *pmkid;
	int mgmt_group_cipher;
}wpa_ie_data;

typedef struct wpa_ie_data        WPA_IE_DATA;

typedef struct authentication_management_frame{
	le16 algorithm;
	le16 sequence;
	le16 status;
}AUTH_MANAGEMENT_FRAME;

typedef struct {
	u8 mac_addr[ETH_ALEN];
	char *device_name;
	char *manufacturer;
	char *model_name;
	char *model_number;
	char *serial_number;
	u8 pri_dev_type[WPS_DEV_TYPE_LEN];
	u32 os_version;
	u8 rf_bands;
}wps_device_data;	
	
typedef struct wps_device_data WPS_DEVICE_DATA;	

typedef struct wps_registrar_device{
	struct wps_registrar_device *next;
	struct wps_device_data dev;
	u8 uuid[WPS_UUID_LEN];
}WPS_REGISTRAR_DEVICE;

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

typedef struct  ieee80211_clone_params{
		char icp_name[IFNAMSIZ];
		uint16_t icp_opmode;
		uint16_t icp_flags;
}IEE80211_CLONE_PARAMS;



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

typedef struct  wps_data{
	WPS_CONTEXT *wps;
	char *key;
	char *essid;
	int registrar;
	int er;
	enum {
		SEND_M1, RECV_M2, SEND_M3, RECV_M4, SEND_M5, RECV_M6, SEND_M7,
		RECV_M8, RECEIVED_M2D, WPS_MSG_DONE, RECV_ACK, WPS_FINISHED,
		SEND_WSC_NACK,
		RECV_M1, SEND_M2, RECV_M3, SEND_M4, RECV_M5, SEND_M6,
		RECV_M7, SEND_M8, RECV_DONE, SEND_M2D, RECV_M2D_ACK
	} state;
	u8 uuid_e[WPS_UUID_LEN];
	u8 uuid_r[WPS_UUID_LEN];
	u8 mac_addr_e[ETH_ALEN];
	u8 nonce_e[WPS_NONCE_LEN];
	u8 nonce_r[WPS_NONCE_LEN];
	u8 psk1[WPS_PSK_LEN];
	u8 psk2[WPS_PSK_LEN];
	u8 snonce[2 * WPS_SECRET_NONCE_LEN];
	u8 peer_hash1[WPS_HASH_LEN];
	u8 peer_hash2[WPS_HASH_LEN];
	WPA_BUF *dh_privkey;
	WPA_BUF *dh_pubkey_e;
	WPA_BUF *dh_pubkey_r;
	u8 authkey[WPS_AUTHKEY_LEN];
	u8 keywrapkey[WPS_KEYWRAPKEY_LEN];
	u8 emsk[WPS_EMSK_LEN];
	WPA_BUF *last_msg;
	u8 *dev_password;
	size_t dev_password_len;
	u16 dev_pw_id;
	int pbc;
	u8 request_type;
	u16 encr_type;
	u16 auth_type;
	u8 *new_psk;
	size_t new_psk_len;
	int wps_pin_revealed;
	WPS_CREDENTIAL cred;
	WPS_DEVICE_DATA peer_dev;
	u16 config_error;
	int ext_reg;
	int int_reg;
	WPS_CREDENTIAL *new_ap_settings;
	void *dh_ctx;
	void (*ap_settings_cb)(void *ctx, const WPS_CREDENTIAL *cred);
	void *ap_settings_cb_ctx;
	WPS_CREDENTIAL *use_cred;
	int use_psk_key;
}WPS_DATA;

typedef struct {
        int last_wps_state;             
        int p1_index;                   
        int p2_index;                   
        char *p1[P1_SIZE];              
        char *p2[P2_SIZE];              
	char *static_p1;			
	char *static_p2;		
	int use_pin_string;		
        enum *key_state key_status;      
	int dh_small;			
	int external_association;	
	int oo_send_nack;
	int win7_compat;
        int delay;                 
        int fail_delay;                
        int recurring_delay;            
	int lock_delay;			
	int ignore_locks;		
        int recurring_delay_count;	
        int eap_terminate;              
        int max_pin_attempts;           
        int rx_timeout;                 
        int timeout_is_nack;            
        int m57_timeout;                
        int out_of_time;                
	unsigned long long resend_timeout_usec;   
        enum *debug_level debug;         
        int eapol_start_count;          
        int fixed_channel;              
	int auto_channel_select;
	int wifi_band;			
	int channel;			
	int repeat_m6;			
	int max_num_probes;		
	int validate_fcs;		
        enum *wsc_op_code opcode;        
        uint8_t eap_id;                
        uint16_t ap_capability;         
        unsigned char bssid[MAC_ADDR_LEN];    
        unsigned char mac[MAC_ADDR_LEN];             
	unsigned char vendor_oui[1+3];	
	unsigned char *htcaps;		
	int htcaps_len;			
	unsigned char *ap_rates;	
	int ap_rates_len;		
	unsigned char *ap_ext_rates;	
	int ap_ext_rates_len;		
	FILE *fp;		
	char *session;			
        char *ssid;                     
        char *iface;                    
        char *pin;                      
	char *exec_string;		
        enum *nack_code nack_reason;     
        pcap_t *handle;                 
	int output_fd;			
	uint64_t uptime;		
        WPS_DATA *wps;           
}globals;

typedef struct globals GLOB;

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

typedef struct {
        uint8_t number;
        uint8_t len;
}tagged_parameter;


typedef struct tagged_parameter TAG_PARAMS;

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


typedef struct dot11_frame_header{
        uint16_t fc;
        uint16_t duration;
        unsigned char addr1[MAC_ADDR_LEN];
        unsigned char addr2[MAC_ADDR_LEN];
        unsigned char addr3[MAC_ADDR_LEN];
        uint16_t frag_seq;
};

typedef struct dot11_frame_header DOT11_FRAME_H;
	
#include "c/lorcon_driver_t.c"
#include "c/tx80211_decode.c"
	
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


char *
lorcon_get_error( context )
      AirLorcon *context
CODE:
	return newSVpv(context->errstr, 0);

AirLorconDriver *
lorcon_find_driver( driver )
      const char *driver


AirLorconDriver *
_lorcon_copy_driver(driver) 
	AirLorconDriver *driver
CODE:
	AirLorconDriver *r;
//      r = (AirLorconDriver *) malloc(sizeof(AirLorconDriver *));
	Newxz(r, 1, AirLorconDriver);
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
      char *interface
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
	return(*(context->openmon_cb))(context);
	

int
lorcon_open_injmon(context)
      AirLorcon *context
      	CODE:
 	if(lorcon_open_injmon(context) == NULL) {
		snprintf(context->errstr, LORCON_STATUS_MAX,  "Driver %s does not support INJMON mode", context->drivername);
		return LORCON_ENOTSUPP;
	}
	return(*(context->openinjmon_cb))(context);
 
AirLorconPacket *
lorcon_packet_from_lcpa(context, lcpa)
	AirLorcon *context							 
	LCPA_META *lcpa
CODE:
	AirLorconPacket *l_packet;
	if (lcpa == NULL){
		return NULL;
	}
	Newxz( l_packet, 1, AirLorconDriver );

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
	//l_packet = (AirLorconPacket *) malloc(sizeof(AirLorconPacket *));
	Newx(l_packet, 1, AirLorconPacket);
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
	u_char *bytes
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
	return(*(context->handler_cb))(context, packet, context->handler_user);


void
lorcon_set_vap(context, vap)
      AirLorcon *context
      const char *vap
 CODE:
  if (context->vapname != NULL){
        Safefree(context->vapname);
  }else{
    context->vapname = savepv(vap);
  }

const char *
lorcon_get_vap(context)
      AirLorcon *context

const char *
lorcon_get_capiface(context)
      AirLorcon *context
CODE:
	if (context->vapname){
		return newSVpv(context->vapname, 0);
	}else{
	return newSVpv(context->ifname, 0);
	}

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
	  return(context->pcap);

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
	return 1;

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
		snprintf(context->errstr, LORCON_STATUS_MAX,  "capture driver %s did not create a pcap context", lorcon_get_driver_name(context));
		return LORCON_ENOTSUPP;
	}
	context->handler_cb = callback;
	context->handler_user = user;
	ret = pcap_loop(context->pcap, counter, lorcon_pcap_handler(user,counter, callback), context);
    if (ret == -1) {
        snprintf(context->errstr, LORCON_STATUS_MAX, "pcap_loop failed: %s", pcap_geterr(context->pcap) );
    }
	return( ret );

      
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
	//wep = (	LORCON_WEP *) malloc(sizeof(LORCON_WEP *) );
	Newx(wep, 1, LORCON_WEP);	
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

int
lorcon_packet_txprep_by_ctx(context, packet, data)
	AirLorcon *context
	AirLorconPacket *packet
	u_char **data

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
CODE:
	if (context->ifconfig_cb == NULL) {
		return -1;
	}else{
	return (*(context->ifconfig_cb))(context, 0);
	}

int
lorcon_get_complex_channel( context, channel )
  AirLorcon *context
  AirLorconChannel *channel
CODE:
	 if (context->getchan_ht_cb == NULL) {
		return -1;
    }else{
    return (*(context->getchan_ht_cb))(context, channel);
	 }

int 
lorcon_parse_ht_channel(in_chanstr, channel)
  char *in_chanstr
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
   AirLorconInterface *i;
   //AirLorconInterface *i =  (AirLorconInterface *) malloc(sizeof(AirLorconInterface *));
   Newxz(i, 1, AirLorconInterface);
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

AV *
lorcon_multi_get_interfaces(ctx)
  AirLorconMulti *ctx
INIT:
        AV *av = newAV();
	AirLorcon *dri;
	AirLorconMulti *TT;
CODE:
   	hv_store(TT, "interface_name",    4, newSVpv(dri->drivername, 0), 0);
        av_push(av, TT);
	return(av);



   

AirLorconInterface *
lorcon_multi_get_next_interface(ctx, intf)
  AirLorconMulti *ctx
  AirLorconInterface *intf
CODE:
	if (intf == NULL){
        	return ctx->interfaces;
	}
RETVAL = newSVpv(intf->next, 0);	
OUTPUT:
RETVAL
	
AirLorcon *
lorcon_multi_interface_get_lorcon(intf)
  AirLorconInterface *intf
CODE:
      return intf->lorcon_intf;

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


int 
drv_madwifing_probe(interface) 
	const char *interface
CODE:
	return 0;

int 
madwifing_getmac_cb(context, mac) 
	AirLorcon *context
	uint8_t **mac
CODE:
	uint8_t int_mac[6];
	if (ifconfig_get_hwaddr(context->vapname, context->errstr, int_mac) < 0) {
		return -1;
	}

	(*mac) = malloc(sizeof(uint8_t) * 6);
	//Newxz(mac, 1, 6);
	//memcpy(*mac, int_mac, 6);
	Copy(int_mac, mac, 6, 1);
	return 6;


int 
madwifing_setmac_cb(context, mac_length, mac) 
	AirLorcon *context
	int mac_length
	uint8_t *mac
CODE:
	short flags;
	if (mac_length != 6) {
		snprintf(context->errstr, LORCON_STATUS_MAX,  "MAC passed to mac80211 driver on %s not 6 bytes, all  802.11 MACs must be 6 bytes", context->vapname);
		return -1;
	}
	if (flags = ifconfig_get_flags(context->vapname, context->errstr, &flags) < 0) {
		return -1;
	}
	if (flags & IFF_UP) {
		if (ifconfig_ifupdown(context->vapname, context->errstr, 0) < 0)
			return -1;
	}
	if (ifconfig_set_hwaddr(context->vapname, context->errstr, mac) < 0){
		return -1;
	}
	if (flags & IFF_UP){
		if (ifconfig_ifupdown(context->vapname, context->errstr, 1) < 0){
			return -1;
		}
	}
	return 1;
	
int 
madwifing_sendpacket(context, packet)
	AirLorcon *context
	AirLorconPacket *packet
CODE:
	int ret;
	u_char rtap_hdr[] = {
		0x00, 0x00, 
		0x0e, 0x00, 
		0x02, 0xc0, 0x00, 0x00, 
		0x00,
		0x00,
		0x00, 0x00,
		0x00, 0x00,
	};

	u_char *bytes;
	int len, freebytes;
	struct iovec iov[2];
	struct msghdr msg = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = iov,
		.msg_iovlen = 2,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = 0,
	};
	if (packet->lcpa != NULL) {
		len = lcpa_size(packet->lcpa);
		freebytes = 1;
		bytes = (u_char *) malloc(sizeof(u_char) * len);
		lcpa_freeze(packet->lcpa, bytes);
	} else if (packet->packet_header != NULL) {
		freebytes = 0;
		len = packet->length_header;
		bytes = (u_char *) packet->packet_header;
	} else {
		freebytes = 0;
		len = packet->length;
		bytes = (u_char *) packet->packet_raw;
	}

	iov[0].iov_base = &rtap_hdr;
	iov[0].iov_len = sizeof(rtap_hdr);
	iov[1].iov_base = bytes;
	iov[1].iov_len = len;
	ret = sendmsg(context->inject_fd, &msg, 0);

	if (freebytes){
		Safefree(bytes);
	}
	return ret;
		
int 
madwifing_openmon_cb(context)
	AirLorcon *context
	
int 
drv_madwifing_init(context) 
  AirLorcon *context
CODE:
	context->openinject_cb = madwifing_openmon_cb(context);
	context->openmon_cb = madwifing_openmon_cb(context);
	context->openinjmon_cb = madwifing_openmon_cb(context);
	context->sendpacket_cb = madwifing_sendpacket();
	context->getmac_cb = madwifing_getmac_cb();
	context->setmac_cb = madwifing_setmac_cb();
	context->auxptr = NULL;
	return 1;
			    
AirLorconDriver *
drv_madwifing_listdriver(drv)
   AirLorconDriver * drv
CODE:
	AirLorconDriver *d;
	//AirLorconDriver *d = (AirLorconDriver *) malloc(sizeof(lorcon_driver_t));
	Newxz(d, 1, AirLorconDriver);
	d->name = savepv("madwifing"); // toggled strdup
	d->details = savepv("Linux madwifi-ng drivers, deprecated by ath5k and ath9k"); // toggled strdup
	d->init_func = drv_madwifing_init(drv);
	d->probe_func = drv_madwifing_probe();
	d->next = drv;
	RETVAL = d;
OUTPUT:
	RETVAL
	
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
tx80211_airjack_capabilities()
CODE:
	return (TX80211_CAP_SNIFF | TX80211_CAP_TRANSMIT | TX80211_CAP_DSSSTX);


#define SIOCSIFFLAGS 0x8914

int 
aj_ifupdown(ifname,  devup) 
	char *ifname
	int devup
CODE:
    struct ifreq ifr;
    int    sock;

    if((sock = aj_getsocket(ifname)) < 0) {
        perror("aj_getsocket");
        close(sock);
        return(-1);
    }

    //memset(&ifr, 0, sizeof(ifr));
    Zero(&ifr, 1, ifr);
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) != 0) {
        perror("ioctl[SIOCGIFFLAGS]");
        close(sock);
        return(1);
    }

    if (devup) {
        ifr.ifr_flags |= IFF_UP;
    } else {
        ifr.ifr_flags &= ~IFF_UP;
    }

    if (ioctl(sock, SIOCSIFFLAGS, &ifr) != 0) {
        perror("ioctl[SIOCSIFFLAGS]");
        close(sock);
        return(1);
    }
    return(0);


#define ETH_P_ALL 0x0003
	
int 
aj_getsocket(ifname) 
	char *ifname

	
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
aj_setnonblock(ifname, nonblock) 
	char *ifname
	int nonblock
CODE:
    int fdflags;
    int sock;

    if((sock = aj_getsocket(ifname)) < 0) {
        perror("aj_getsocket");
        close(sock);
        return(-1);
    }

    fdflags = fcntl(sock, F_GETFL, 0);
    if (fdflags == -1) {
                perror("fcntl[F_GETFL]");
        close(sock);
        return (-1);
    }
    if (nonblock)
        fdflags |= O_NONBLOCK;
    else
        fdflags &= ~O_NONBLOCK;
    if (fcntl(sock, F_SETFL, fdflags) == -1) {
                perror("fcntl[F_SETFL]");
        close(sock);
        return (-1);
    }
    close(sock);
    return (0);



int 
aj_getnonblock(ifname) 
	char *ifname
CODE:
    int flags, mode, sock;

    if((sock = aj_getsocket(ifname)) < 0) {
        perror("aj_getsocket");
        close(sock);
        return(-1);
    }

    flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) {
        perror("fcntl[F_GETFL]");
        close(sock);
        return(-1);
    }

    mode = flags & O_NONBLOCK;
    close(sock);
    return(mode);
	

int 
aj_setmode(ifname,  mode)
  char *ifname
  int mode

int 
aj_setmac(ifname, mac)
  char *ifname
  uint8_t *mac
CODE:
	struct aj_config ajconf;
	struct ifreq req;
	int sock;
	if ((sock = aj_getsocket(ifname)) < 0) {
		close(sock);
		return (-1);
	}
	req.ifr_data = (char *)&ajconf;
	strnNE(req.ifr_name, ifname, sizeof(req.ifr_name));
	if (ioctl(sock, SIOCAJGMODE, &req) < 0) {
		close(sock);
		return (-1);
	}
	memcpy(ajconf.ownmac, mac, 6);
	//StructCopy(mac, ajconf.ownmac, 6);
	if (ioctl(sock, SIOCAJSMODE, &req) < 0) {
		close(sock);
		return (-1);
	}
	close(sock);
	return (0);	
	

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
aj_xmitframe(interface_name, xmit, len, errstr)
  char *interface_name
  uint8_t *xmit
  int len
  char *errstr


int 
aj_setchannel(ifname,channel)
  char *ifname
  int channel
CODE:
    struct aj_config ajconf;
    struct ifreq req;
    int    sock;
    if((sock = aj_getsocket(ifname)) < 0) {
        perror("aj_getsocket");
        close(sock);
        return(-1);
    }

    req.ifr_data = (char *)&ajconf;
    strncpy(req.ifr_name, ifname, sizeof(req.ifr_name)); //TO MODIFY
    /* populate the structure */
    if (ioctl(sock, SIOCAJGMODE, &req) < 0) {
        close(sock); 
        return(-1);
    }
    ajconf.channel = channel;
    if (ioctl(sock, SIOCAJSMODE, &req) < 0) {
        close(sock); 
        return(-1);
    }
    close(sock); 
    return(0);

  
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

#define IW_ESSID_MAX_SIZE   32
#define	SIOCSIWESSID   0x8B1A

int
iwconfig_set_ssid(input_dev, errstr, input_essid)
   const char *input_dev
   char *errstr
   char *input_essid
CODE:
	struct iwreq wrq;
	int skfd;
	char essid[IW_ESSID_MAX_SIZE + 1];

	if (input_essid == NULL) {
		essid[0] = '\0';
	} else {
		snprintf(essid, IW_ESSID_MAX_SIZE + 1, "%s", input_essid);
	}
	if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		snprintf(errstr, LORCON_STATUS_MAX, "Failed to create ioctl socket to set SSID on %s: %s", input_dev, strerror(errno));
		return -1;
	}
	strncpy(wrq.ifr_name, input_dev, IFNAMSIZ);
	wrq.u.essid.pointer = (caddr_t) essid;
	wrq.u.essid.length = sv_len(essid) + 1;
	wrq.u.essid.flags = 1;
	if (ioctl(skfd, SIOCSIWESSID, &wrq) < 0) {
		snprintf(errstr, LORCON_STATUS_MAX, "Failed to set SSID on %s: %s", input_dev, strerror(errno));
		close(skfd);
		return -1;
	}
	close(skfd);
	return 0;

#define SIOCGIWESSID  0x8B1B

int
iwconfig_get_ssid(input_dev, errstr, input_essid)
   const char *input_dev   
   char *errstr
   char *input_essid
CODE:
	struct iwreq wrq;
	int skfd;
	char essid[IW_ESSID_MAX_SIZE + 1];

	if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		snprintf(errstr, LORCON_STATUS_MAX,"Failed to create socket to fetch SSID on %s: %s", input_dev, strerror(errno));
		return -1;
	}
	strncpy(wrq.ifr_name, input_dev, IFNAMSIZ);
	wrq.u.essid.pointer = (caddr_t) essid;
	wrq.u.essid.length = IW_ESSID_MAX_SIZE + 1;
	wrq.u.essid.flags = 0;

	if (ioctl(skfd, SIOCGIWESSID, &wrq) < 0) {
		snprintf(errstr, LORCON_STATUS_MAX, "Failed to fetch SSID from %s: %s", input_dev, strerror(errno));
		close(skfd);
		return -1;
	}

	snprintf(input_essid, min(IW_ESSID_MAX_SIZE, wrq.u.essid.length) + 1, "%s", (char *)wrq.u.essid.pointer);
	close(skfd);
	return 0;


#define SIOCGIWNAME   0x8B01

int
iwconfig_get_name(input_dev, errstr, input_name)
   const char *input_dev
   char *errstr
   char *input_name
CODE:
	struct iwreq wrq;
	int skfd;

	if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		snprintf(errstr, LORCON_STATUS_MAX, "Failed to create socket to get name on %s: %s", input_dev, strerror(errno));
		return -1;
	}

	strncpy(wrq.ifr_name, input_dev, IFNAMSIZ);

	if (ioctl(skfd, SIOCGIWNAME, &wrq) < 0) {
		snprintf(errstr, LORCON_STATUS_MAX, "Failed to get name on %s :%s", input_dev, strerror(errno));
		close(skfd);
		return -1;
	}

	snprintf(input_name, IFNAMSIZ, "%s", wrq.u.name);

	close(skfd);
	return 0;

int 
floatchan2int(input_chan)
	float input_chan
CODE:
    if (input_chan == 0){
        return 0;
	}
    if (input_chan == 2484){
        return 14;
	}
    else if (input_chan < 2484){
        return (input_chan - 2407) / 5;
	}
    else if (input_chan >= 4910 && input_chan <= 4980){
        return (input_chan - 4000) / 5;
	}
    else if (input_chan <= 45000){
        return (input_chan - 5000) / 5;
	}
    else if (input_chan >= 58320 && input_chan <= 64800){
        return (input_chan - 56160) / 2160;
	}
    return input_chan;
	
float 
iwfreq2float(inreq)
	iwreq *inreq
CODE:
	return ((float)inreq->u.freq.m) * pow(10, inreq->u.freq.e);
	
	
#define SIOCGIWFREQ   0x8B05

int
iwconfig_get_channel(input_dev, errstr)
   const char *input_dev
   char *errstr
CODE:
	struct iwreq wrq;
	int skfd;

	if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		snprintf(errstr, LORCON_STATUS_MAX, "Failed to create AF_INET DGRAM socket %d:%s", errno, strerror(errno));
		return -1;
	}

	//memset(&wrq, 0, sizeof(struct iwreq));
	Zero(&wrq, 1, iwreq);
	strncpy(wrq.ifr_name, input_dev, IFNAMSIZ);

	if (ioctl(skfd, SIOCGIWFREQ, &wrq) < 0) {
		snprintf(errstr, LORCON_STATUS_MAX, "channel get ioctl failed %d:%s", errno, strerror(errno));
		close(skfd);
		return -1;
	}

	close(skfd);
	return newSVpv((floatchan2int(iwfreq2float(&wrq))), 0);

#define IW_FREQ_FIXED   0x01

int
iwconfig_set_channel(input_dev, errstr, input_channel)
   const char *input_dev
   char *errstr
   int input_channel
CODE:
	struct iwreq wrq;
	int skfd;

	if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		snprintf(errstr, LORCON_STATUS_MAX, "Failed to create AF_INET DGRAM socket %d:%s", errno, strerror(errno));
		return -1;
	}
	//memset(&wrq, 0, sizeof(struct iwreq));
	Zero(&wrq, 1, iwreq);
	strncpy(wrq.ifr_name, input_dev, IFNAMSIZ);
#ifdef IW_FREQ_FIXED
	wrq.u.freq.flags = IW_FREQ_FIXED;
#endif

	if (input_channel > 1024) {
		iwfloat2freq(input_channel * 1e6, &wrq.u.freq);
	}else{
		iwfloat2freq(input_channel, &wrq.u.freq);
	}

	if (ioctl(skfd, SIOCSIWFREQ, &wrq) < 0) {
		struct timeval tm;
		tm.tv_sec = 0;
		tm.tv_usec = 5000;
		select(0, NULL, NULL, NULL, &tm);

		if (ioctl(skfd, SIOCSIWFREQ, &wrq) < 0) {
			snprintf(errstr, LORCON_STATUS_MAX, "Failed to set channel %d %d:%s", input_channel, errno, strerror(errno));
			close(skfd);
			return -1;
		}
	}
	close(skfd);
	return 0;
	
int 
iwconfig_get_mode(input_dev, errstr)
   const char *input_dev
   char *errstr
CODE:
        struct iwreq wrq;
	int skfd;
	if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		snprintf(errstr, LORCON_STATUS_MAX, "Failed to create AF_INET DGRAM socket %d:%s", errno, strerror(errno));
		return -1;
	}

	//memset(&wrq, 0, sizeof(struct iwreq));
	Zero(&wrq, 1, iwreq);
	strncpy(wrq.ifr_name, input_dev, IFNAMSIZ);

	if (ioctl(skfd, SIOCGIWMODE, &wrq) < 0) {
		snprintf(errstr, LORCON_STATUS_MAX, "mode get ioctl failed %d:%s", errno, strerror(errno));
		close(skfd);
		return -1;
	}
	close(skfd);
	return (wrq.u.mode);
	
int
iwconfig_set_mode(input_dev, in_err, tx80211_mode)
	const char *input_dev
	char *in_err
	int tx80211_mode
CODE:
	struct iwreq wrq;
	int skfd;

	if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		snprintf(in_err, LORCON_STATUS_MAX, "Failed to create AF_INET DGRAM socket %d:%s", errno, strerror(errno));
		return -1;
	}

	//memset(&wrq, 0, sizeof(struct iwreq));
	Zero(&wrq, 1, iwreq);
	strncpy(wrq.ifr_name, input_dev, IFNAMSIZ);

	wrq.u.mode = tx80211_mode;

	if (ioctl(skfd, SIOCSIWMODE, &wrq) < 0) {
		snprintf(in_err, LORCON_STATUS_MAX, "mode set ioctl failed %d:%s", errno, strerror(errno));
		close(skfd);
		return -1;
	}

	close(skfd);
	return 0;
	
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

	//memset(&if_req, 0, sizeof(if_req));
	Zero(if_req, 1, if_req);
	//memcpy(if_req->ifr_name, context->ifname, IFNAMSIZ);
	Copy(context->ifname, if_req->ifr_name, IFNAMSIZ, 0);	
	if_req->ifr_name[IFNAMSIZ - 1] = 0;
	if (ioctl(context->inject_fd, SIOCGIFINDEX, &if_req) < 0) {
		snprintf(context->errstr, LORCON_STATUS_MAX, "failed to get interface idex: %s", strerror(errno));
		close(context->inject_fd);
		pcap_close(context->pcap);
		return -1;
	}

	//memset(&sa_ll, 0, sizeof(sa_ll));
	Zero(sa_ll, 1, sa_ll);
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
 	AirLorconDriver *d;
	//AirLorconDriver *d = (AirLorconDriver *) malloc(sizeof(AirLorconDriver *));
	Newxz(d, 1, AirLorconDriver);
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
	IEE80211_CLONE_PARAMS *cp;
	//IEE80211_CLONE_PARAMS *cp = malloc(sizeof(IEE80211_CLONE_PARAMS *));
	Newxz(cp, 1, IEE80211_CLONE_PARAMS);
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

	//memset(&ifr, 0, sizeof(ifr));
	Zero(&ifr, 1, ifr); 
	//memset(&cp, 0, sizeof(cp));
	Zero(&cp, 1, cp);
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


int 
wtinj_close(wtinj)
	TX80211 *wtinj
CODE:
	return( close(wtinj->raw_fd) );

int 
wtinj_setchannel(wtinj, channel)
	TX80211 *wtinj
	int channel
CODE:
	wtinj->channel = channel;
        return (iwconfig_set_channel(wtinj->ifname, wtinj->errstr, channel));
	

int 
wtinj_getchannel(wtinj)
	TX80211 *wtinj
CODE:
	//return (iwconfig_get_channel(wtinj->ifname, wtinj->errstr));
	return(int) (wtinj->channel);
		
int 
wtinj_setmode(wtinj, mode)
	TX80211 *wtinj
	int mode
CODE:
	wtinj->mode = mode;
	return(iwconfig_set_mode(wtinj->ifname, wtinj->errstr, mode));

int 
wtinj_getmode(wtinj)
	TX80211 *wtinj
CODE:
	return(wtinj->mode);


int 
wtinj_setfuncmode(wtinj, funcmode)
	TX80211 *wtinj
	int funcmode

int 
wtinj_selfack(wtinj, addr)
	TX80211 *wtinj
	uint8_t *addr


int 
tx80211_rt2570_init(input_tx)
	TX80211 *input_tx
CODE:
	input_tx->capabilities = tx80211_rt2570_capabilities();
	input_tx->open_callthrough = rt2570_open();
	input_tx->close_callthrough = wtinj_close();
	input_tx->setmode_callthrough = wtinj_setmode();
	input_tx->getmode_callthrough = wtinj_getmode();
	input_tx->getchan_callthrough = wtinj_getchannel();
	input_tx->setchan_callthrough = wtinj_setchannel();
	input_tx->txpacket_callthrough = rt2570_send();
	input_tx->setfuncmode_callthrough = wtinj_setfuncmode();
	return 0;


int 
tx80211_rt2570_capabilities()
CODE:
	return (TX80211_CAP_SNIFF | TX80211_CAP_TRANSMIT |  TX80211_CAP_BSSTIME | TX80211_CAP_FRAG | TX80211_CAP_CTRL | TX80211_CAP_DURID);


int 
iwconfig_get_intpriv(in_dev, privcmd, val, errstr)
	char *in_dev
	char *privcmd
	int *val
	char *errstr

int 
iwconfig_set_charpriv(in_dev, privcmd, val, errstr)
	char *in_dev
	char *privcmd
	char *val
	char *errstr

int 
rt2570_open(input_tx)
	TX80211 *input_tx
CODE:
	char errstr[TX80211_STATUS_MAX];
	if (iwconfig_set_charpriv(input_tx->ifname, "rfmontx", "1", errstr) >= 0){
		return(wtinj_open(input_tx));
	}
	if (iwconfig_set_intpriv(input_tx->ifname, "rfmontx", 1, 0, errstr) >= 0){
		return(wtinj_open(input_tx));
	}

	fprintf(stderr, "Error enabling rfmontx private ioctl: %s\n", errstr);
	return -1;


int 
rt2570_send(input_tx, input_pkt)
	TX80211 *input_tx
	TX80211_PACKET *input_pkt
CODE:
	int ret;

	if (!(input_tx->raw_fd > 0)) {
		return 0;
	}

	ret = write(input_tx->raw_fd, input_pkt->packet, input_pkt->plen);

	usleep(2);

	if (ret < 0){
		return TX80211_ENOTX;
	}
	return (ret);
	
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

int 
tx80211_mac80211_capabilities()
CODE:
return (TX80211_CAP_SNIFF | TX80211_CAP_TRANSMIT | TX80211_CAP_SELFACK | TX80211_CAP_DSSSTX);


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
	//Newx(data, 1, length);	
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

	//ret = (AirLorconPacket *) malloc(sizeof(AirLorconPacket *));
	Newxz(ret, 1, AirLorconPacket);
	//memset(ret, 0, sizeof(AirLorconPacket));
	Zero(ret, 1, AirLorconPacket);
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
        //return d11extra->bssid_mac;
 	  HV *out = newHV();
 	  SV *out_ref = newRV_noinc((SV *)out);
 	  hv_store(out, "bssid_mac",    4, newSVpv(d11extra->bssid_mac, 0), 0);
	  return(out_ref);
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



	
int
pcap_can_set_rfmon(p)
	Pcap *p
CODE:
	return (p->can_set_rfmon_op(p));

#define PCAP_ERROR_ACTIVATED		-4

int
pcap_set_rfmon(p, rfmon)
	Pcap *p
	int rfmon
CODE:
	if(! p->activated){
		return (PCAP_ERROR_ACTIVATED);
	}else{
		
	p->opt->rfmon = rfmon;
	return 0;
	}

int
pcap_inject(p, buf, size)
	Pcap *p
	const void *buf
	size_t size
CODE:
	if (size > INT_MAX) {
		return (PCAP_ERROR);
	}

	if (size == 0) {
		return (PCAP_ERROR);
	}
	return(p->inject_op(p, buf, (int)size));

	
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
	char *interface
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
    //rtf_extra =  (RTFILE_EXTRA_LORCON *) malloc(sizeof(RTFILE_EXTRA_LORCON *));
    Newx(rtf_extra, 1, RTFILE_EXTRA_LORCON);
    rtf_extra->last_ts.tv_sec = 0;
    rtf_extra->last_ts.tv_usec = 0;
    context->auxptr = rtf_extra;
	return 1;


     
AirLorconDriver *
drv_file_listdriver(drv)
     AirLorconDriver *drv
CODE:
	AirLorconDriver *d; 
	//d = (AirLorconDriver *) malloc(sizeof(AirLorconDriver *));
	Newx(d, 1, AirLorconDriver);
	AirLorconDriver *rtd; 
	//rtd = (AirLorconDriver *) malloc(sizeof(AirLorconDriver *));
	Newx(rtd, 1, AirLorconDriver);
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
tx80211_bcm43xx_init(input_tx)
	TX80211 *input_tx
CODE:
	input_tx->capabilities = tx80211_bcm43xx_capabilities();
	input_tx->open_callthrough = bcm43xx_open();
	input_tx->close_callthrough = bcm43xx_close();
	input_tx->setmode_callthrough = wtinj_setmode();
	input_tx->getmode_callthrough = wtinj_getmode();
	input_tx->getchan_callthrough = wtinj_getchannel();
	input_tx->setchan_callthrough = wtinj_setchannel();
	input_tx->txpacket_callthrough = wtinj_send();
	input_tx->setfuncmode_callthrough = wtinj_setfuncmode();
	return 0;


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
	inject_nofcs_location  = (char*) malloc(strlen(in_tx->ifname) + strlen(inject_nofcs_pname) + 5); 
	int ifname_l = strlen(in_tx->ifname) + strlen(inject_nofcs_pname) + 5;
	//Newxz(inject_nofcs_location , 1, (strlen(in_tx->ifname) + strlen(inject_nofcs_pname) + 5) );
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
	Safefree(input_list->injnum);
	Safefree(input_list);


TX80211_CARDLIST *
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
	PUSHs(sv_2mortal(newSVpv(cardlist->descriptions[i], 0)));
	//PUSHs(sv_2mortal(newSVpv(cardlist->capabilities[i], 0)));
	//PUSHs(sv_2mortal(newSVpv(cardlist->injnum[i], 0)));
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
	int frame_l = sizeof(*frame)+ payloadlen;
	//Newxz(frame, 1, frame + payloadlen);
	if (frame == NULL) {
		snprintf(wginj->errstr, TX80211_STATUS_MAX, "wlan-ng send unable to allocate memory buffer");
		return TX80211_ENOTX;
	}

	//memset(frame, 0, sizeof(*frame));
	Zero(frame, 1, frame);
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
mac80211_sendpacket(context, packet) 
	AirLorcon *context
	AirLorconPacket *packet
CODE:
	int ret;
	u_char rtap_hdr[] = {
		/* rt version */
		0x00, 0x00, 
		/* rt len */
		0x0e, 0x00, 
		/* rt bitmap, flags, tx, rx */
		0x02, 0xc0, 0x00, 0x00, 
		/* Allow frgmentation */
		IEEE80211_RADIOTAP_F_FRAG,
		/* pad */
		0x00,
		/* rx and tx set to inject */
		0x00, 0x00,
		0x00, 0x00,
	};

	u_char *bytes;
	int len, freebytes;
	struct iovec iov[2];

	struct msghdr msg = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = iov,
		.msg_iovlen = 2,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = 0,
	};

	if (packet->lcpa != NULL) {
		len = lcpa_size(packet->lcpa);
		freebytes = 1;
		bytes = (u_char *) malloc(sizeof(u_char) * len);
		//Newxz(bytes, 1, len);
		lcpa_freeze(packet->lcpa, bytes);
	} else if (packet->packet_header != NULL) {
		freebytes = 0;
		len = packet->length_header;
		bytes = (u_char *) packet->packet_header;
	} else {
		freebytes = 0;
		len = packet->length;
		bytes = (u_char *) packet->packet_raw;
	}

	iov[0].iov_base = &rtap_hdr;
	iov[0].iov_len = sizeof(rtap_hdr);
	iov[1].iov_base = bytes;
	iov[1].iov_len = len;

	ret = sendmsg(context->inject_fd, &msg, 0); // sendmsg to a socket

	snprintf(context->errstr, LORCON_STATUS_MAX, "drv_mac80211 failed to send packet: %s", strerror(errno));

	if (freebytes){
		free(bytes);
	}
	RETVAL = ret;
OUTPUT:
	RETVAL

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
	//memset(&if_req, 0, sizeof(if_req));
	Zero(&if_req, 1, if_req);
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

	//memset(&sa_ll, 0, sizeof(sa_ll));
	Zero(&sa_ll, 1, sa_ll);
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
mac80211_ifconfig_cb(context, up) 
	AirLorcon *context
	int up
CODE:
	return ifconfig_ifupdown(context->vapname, context->errstr, up);


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
drv_mac80211_init(context) 
	AirLorcon *context
CODE:
	AirLorcon_MAC80211 *extras; // declare extras
	//struct mac80211_lorcon *extras =  (struct mac80211_lorcon *) malloc(sizeof(struct mac80211_lorcon));
	Newxz(extras, 1, AirLorcon_MAC80211);
	//memset(extras, 0, sizeof(struct mac80211_lorcon));
	Zero(extras, 1, AirLorcon_MAC80211);
	context->openinject_cb = mac80211_openmon_cb(context);
	context->openmon_cb = mac80211_openmon_cb(context);
	context->openinjmon_cb = mac80211_openmon_cb(context);
	context->ifconfig_cb = mac80211_ifconfig_cb();
	context->sendpacket_cb = mac80211_sendpacket();
	context->setchan_cb = mac80211_setchan_cb();
	context->getchan_cb = mac80211_getchan_cb();
    	context->setchan_ht_cb = mac80211_setchan_ht_cb();
	context->getmac_cb = mac80211_getmac_cb();
	context->setmac_cb = mac80211_setmac_cb();
	context->auxptr = extras;
	return 1;

     
AirLorconDriver  *
drv_mac80211_listdriver(head) 
	AirLorconDriver *head
CODE:
	AirLorconDriver *d;
	//AirLorconDriver *d = (AirLorconDriver *) malloc(sizeof(AirLorconDriver *));
	Newxz(d, 1, AirLorconDriver);
	AirLorcon *interface;
	d->name = savepv("mac80211");
	d->details = savepv("Linux mac80211 kernel drivers, includes all in-kernel drivers on modern systems");
	d->init_func = drv_mac80211_init(interface);
	d->probe_func = drv_mac80211_probe();
	d->next = head;
	return d;
	



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



int 
wginj_open(wginj)
	TX80211 *wginj
CODE:
	int err;
	struct ifreq if_req;
	SOCKADDR_LL sa_ll;

	wginj->raw_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (wginj->raw_fd < 0){
		return -1;
		}

	//memset(&if_req, 0, sizeof if_req);
	Zero(&if_req, 1, if_req);	
	//memcpy(if_req.ifr_name, wginj->ifname, IFNAMSIZ);
	Copy(wginj->ifname, if_req.ifr_name, IFNAMSIZ, 1);
	if_req.ifr_name[IFNAMSIZ - 1] = 0;
	err = ioctl(wginj->raw_fd, SIOCGIFINDEX, &if_req);
	if (err < 0) {
		snprintf(wginj->errstr, TX80211_STATUS_MAX, "wlan-ng unable to find interface index (SIOCGIFINDEX): %s", strerror(errno));
		close(wginj->raw_fd);
		return -2;
	}

	//memset(&sa_ll, 0, sizeof sa_ll);
	Zero(&sa_ll, 1, sa_ll);	
	sa_ll.sll_family = AF_PACKET;
	sa_ll.sll_protocol = htons(ETH_P_80211_RAW);
	sa_ll.sll_ifindex = if_req.ifr_ifindex;
	err = bind(wginj->raw_fd, (struct sockaddr *)&sa_ll, sizeof sa_ll);
	if (err != 0) {
		snprintf(wginj->errstr, TX80211_STATUS_MAX, "wlan-ng unable to bind() socket: %s",
				 strerror(errno));
		close(wginj->raw_fd);
		return -3;
	}

	return 0;


int 
wginj_close(wginj)
	TX80211 *wginj
CODE:	
	return close(wginj->raw_fd);


int 
wginj_getchannel(wginj)
	TX80211 *wginj
CODE: 	
	char errstr[TX80211_STATUS_MAX];	/* Not used for now */
	return (iwconfig_get_channel(wginj->ifname, errstr));


int 
wginj_setchannel(wginj, channel)
	TX80211 *wginj
	int channel
CODE:
	char cmdline[2048];
	int ret;

	snprintf(cmdline, sizeof(cmdline), "wlanctl-ng %s lnxreq_wlansniff channel=%d enable=true >/dev/null 2>&1", wginj->ifname, channel);
	ret = system(cmdline);
	if (ret != 0) {
		return -1;
	}else{	return 0; }

int 
wginj_getmode(wginj)
	TX80211 *wginj
CODE:
	char errstr[TX80211_STATUS_MAX];
	return ( iwconfig_get_mode(wginj->ifname, errstr) );

#define TX80211_MODE_MONITOR	6 
#define TX80211_MODE_INFRA	2
#define TX80211_MODE_AUTO	0  
#define TX80211_MODE_ADHOC	1 
#define TX80211_MODE_MASTER	3   
#define TX80211_MODE_REPEAT	4   
#define TX80211_MODE_SECOND	5   

int 
wginj_setmode(wginj, mode)
	TX80211 *wginj
	int mode
CODE:
	char cmdline[2048];
	int currentchan = 0;

	switch (mode) {
	case TX80211_MODE_MONITOR:
		currentchan = wginj_getchannel(wginj);
		snprintf(cmdline, sizeof(cmdline), "wlanctl-ng %s lnxreq_wlansniff channel=%d enable=true >/dev/null 2>&1", 
			wginj->ifname, currentchan);
		return (system(cmdline));

	case TX80211_MODE_INFRA:
		currentchan = wginj_getchannel(wginj);
		snprintf(cmdline, sizeof(cmdline), "wlanctl-ng %s lnxreq_wlansniff channel=%d enable=false >/dev/null 2>&1", 
			wginj->ifname, currentchan);
		return (system(cmdline));

	case TX80211_MODE_AUTO:
	case TX80211_MODE_ADHOC:
	case TX80211_MODE_MASTER:
	case TX80211_MODE_REPEAT:
	case TX80211_MODE_SECOND:
	default:
		return -1;	
	}


int 
tx80211_wlanng_capabilities()
CODE:
	return (TX80211_CAP_SNIFF | TX80211_CAP_TRANSMIT | TX80211_CAP_DSSSTX);



int 
tx80211_wlanng_init(input_tx)
	TX80211 *input_tx
CODE:
	input_tx->capabilities = tx80211_wlanng_capabilities();
	input_tx->open_callthrough = wginj_open();
	input_tx->close_callthrough = wginj_close();
	input_tx->setmode_callthrough = wginj_setmode();
	input_tx->getmode_callthrough = wginj_getmode();
	input_tx->getchan_callthrough = wginj_getchannel();
	input_tx->setchan_callthrough = wginj_setchannel();
	input_tx->txpacket_callthrough = wginj_send();
	input_tx->setfuncmode_callthrough = NULL;
	return 0;


int 
tx80211_rtl8180_capabilities()
CODE:
	return (TX80211_CAP_SNIFF | TX80211_CAP_TRANSMIT); 

int
tx80211_rtl8180_init(input_tx)
	TX80211 *input_tx
CODE:
	input_tx->capabilities = tx80211_rtl8180_capabilities();
	input_tx->open_callthrough = wtinj_open();
	input_tx->close_callthrough = wtinj_close();
	input_tx->setmode_callthrough = wtinj_setmode();
	input_tx->getmode_callthrough = wtinj_getmode();
	input_tx->getchan_callthrough = wtinj_getchannel();
	input_tx->setchan_callthrough = wtinj_setchannel();
	input_tx->txpacket_callthrough = wtinj_send();
	input_tx->setfuncmode_callthrough = wtinj_setfuncmode();
	return 0;




int 
tx80211_rt73_init(input_tx)
	TX80211 *input_tx
CODE:
	input_tx->capabilities = tx80211_rt73_capabilities();
	input_tx->open_callthrough = rt73_open();
	input_tx->close_callthrough = rt73_close();
	input_tx->setmode_callthrough = wtinj_setmode();
	input_tx->getmode_callthrough = wtinj_getmode();
	input_tx->getchan_callthrough = wtinj_getchannel();
	input_tx->setchan_callthrough = wtinj_setchannel();
	input_tx->txpacket_callthrough = wtinj_send();
	input_tx->setfuncmode_callthrough = wtinj_setfuncmode();
	return 0;


#define TX80211_CAP_OFDMTX	4096
#define TX80211_CAP_MIMOTX	8192

int 
tx80211_rt73_capabilities()
CODE:
	 return (TX80211_CAP_SNIFF | TX80211_CAP_TRANSMIT | TX80211_CAP_SEQ | TX80211_CAP_BSSTIME | TX80211_CAP_FRAG | TX80211_CAP_CTRL | TX80211_CAP_DURID | TX80211_CAP_SNIFFACK | TX80211_CAP_DSSSTX | TX80211_CAP_OFDMTX);

int 
rt73_open(input_tx)
	TX80211 *input_tx
CODE:
	char errstr[TX80211_STATUS_MAX];
	if (iwconfig_set_intpriv(input_tx->ifname, "rfmontx", 1, 0, errstr) != 0) {
		if (iwconfig_set_charpriv(input_tx->ifname, "rfmontx", "1", errstr) != 0) {
			snprintf(input_tx->errstr, TX80211_STATUS_MAX, "Error enabling rfmontx private ioctl: %s\n", errstr);
			return -1;
		}
	}
	return(wtinj_open(input_tx));


int
rt73_close(input_tx)
	TX80211 *input_tx
CODE:
	char errstr[TX80211_STATUS_MAX];

	if (iwconfig_set_charpriv(input_tx->ifname, "rfmontx", "0", errstr) != 0) {
		snprintf(input_tx->errstr, TX80211_STATUS_MAX, "Error disabling rfmontx private ioctl: %s\n", errstr);
		return -1;
	}

	return(wtinj_close(input_tx));
	
void 
tx80211_initpacket(input_packet) 
	TX80211_PACKET *input_packet
CODE:
	//memset(in_packet, 0, sizeof(TX80211_PACKET));
	Zero(input_packet, 1, TX80211_PACKET);

void 
tx80211_setlocaldlt(input_tx, in_dlt)
	TX80211 *input_tx
	int in_dlt
CODE:
	input_tx->dlt = in_dlt;


int 
tx80211_getdlt(input_tx)
	TX80211 *input_tx
CODE:	
	int ret_val = input_tx->dlt;
	return( ret_val );

char *
tx80211_getdrivername(in_inj)
	int in_inj
CODE:
	TX80211_CARDLIST *cardlist = NULL;
	int i;
	char *ret;

	cardlist = tx80211_getcardlist();

	for (i = 1; i < cardlist->num_cards; i++) {
		if (cardlist->injnum[i] == in_inj) {
			ret = savepv(cardlist->cardnames[i]);
			tx80211_freecardlist(cardlist);
			return ret;
		}
	}

	tx80211_freecardlist(cardlist);
	return NULL;



int 
tx80211_rt2500_init(input_tx)
	TX80211 *input_tx
CODE:
	input_tx->capabilities = tx80211_rt2500_capabilities();
	input_tx->open_callthrough = rt2500_open();
	input_tx->close_callthrough = rt2500_close();
	input_tx->setmode_callthrough = wtinj_setmode();
	input_tx->getmode_callthrough = wtinj_getmode();
	input_tx->getchan_callthrough = wtinj_getchannel();
	input_tx->setchan_callthrough = wtinj_setchannel();
	input_tx->txpacket_callthrough = wtinj_send();
	input_tx->setfuncmode_callthrough = wtinj_setfuncmode();
	return 0;


int 
tx80211_rt2500_capabilities()
CODE:
	 return (TX80211_CAP_SNIFF | TX80211_CAP_TRANSMIT | TX80211_CAP_SEQ | TX80211_CAP_BSSTIME | TX80211_CAP_FRAG | TX80211_CAP_CTRL | TX80211_CAP_DURID | TX80211_CAP_DSSSTX);



int 
rt2500_open(input_tx)
	TX80211 *input_tx
CODE:
	char errstr[TX80211_STATUS_MAX];
	if (iwconfig_set_charpriv(input_tx->ifname, "rfmontx", "1", errstr) != 0) {
		snprintf(input_tx->errstr, TX80211_STATUS_MAX, "Error enabling rfmontx private ioctl: %s\n", errstr);
		return -1;
	}
	return(wtinj_open(input_tx));


int 
rt2500_close(input_tx)
	TX80211 *input_tx
CODE:
	char errstr[TX80211_STATUS_MAX];
	if (iwconfig_set_charpriv(input_tx->ifname, "rfmontx", "0", errstr) != 0) {
		snprintf(input_tx->errstr, TX80211_STATUS_MAX, "Error disabling rfmontx private ioctl: %s\n", errstr);
		return -1;
	}
	return(wtinj_close(input_tx));
	
#define TX80211_ENOERR			0


int 
tx80211_init(input_tx, input_ifname, input_injector)
	TX80211 *input_tx
	char *input_ifname
	int input_injector
CODE:
	int ret = TX80211_ENOERR;
	//memset(in_tx, 0, sizeof(struct tx80211));
	Zero(input_tx, 1, TX80211);
	strncpy(input_tx->ifname, input_ifname, MAX_IFNAME_LEN);
	input_tx->injectortype = input_injector;

	switch (input_injector) {
	case INJ_WLANNG:
		ret = tx80211_wlanng_init(input_tx);
		break;

	case INJ_AIRJACK:
		ret = tx80211_airjack_init(input_tx);
		break;

	case INJ_PRISM54:
		ret = tx80211_prism54_init(input_tx);
		break;

	case INJ_MADWIFIOLD:
		ret = tx80211_madwifiold_init(input_tx);
		break;

	case INJ_MADWIFING:
		ret = drv_madwifing_init(input_tx);
		break;

	case INJ_HOSTAP:
		ret = tx80211_hostap_init(input_tx);
		break;

	case INJ_RT2500:
		ret = tx80211_rt2500_init(input_tx);
		break;

	case INJ_RT2570:
		ret = tx80211_rt2570_init(input_tx);
		break;

	case INJ_RT73:
		ret = tx80211_rt73_init(input_tx);
		break;

	case INJ_RTL8180:
		ret = tx80211_rtl8180_init(input_tx);
		break;

	case INJ_ZD1211RW:
		ret = tx80211_zd1211rw_init(input_tx);
		break;

	case INJ_BCM43XX:
		ret = tx80211_bcm43xx_init(input_tx);
		break;

	case INJ_MAC80211:
		ret = drv_mac80211_init(input_tx);
		break;
}

#define TX80211_ENOINIT	-12
#define TX80211_ENOHANDLER	-11
#define TX80211_ENOTCAPAB	-13

int 
tx80211_txpacket(input_tx, input_packet )
	TX80211 *input_tx
	TX80211_PACKET *input_packet
CODE:
	if (input_tx->txpacket_callthrough == NULL) {
		snprintf(input_tx->errstr, TX80211_STATUS_MAX,  "txpacket callthrough handler not implemented");
		return TX80211_ENOHANDLER;
	}
	return (input_tx->txpacket_callthrough) (input_tx, input_packet);

int 
tx80211_get_capabilities(input_tx)
	TX80211 *input_tx
CODE:
	return input_tx->capabilities;
	
int 
tx80211_setmodulation(input_tx,  input_packet, modulation)
	TX80211 *input_tx
	TX80211_PACKET *input_packet
	int modulation
CODE:
	if (input_tx->injectortype == INJ_NODRIVER) {
		snprintf(input_tx->errstr, TX80211_STATUS_MAX, "setmodulation: driver type not intialized");
		return TX80211_ENOINIT;
	}

	if ((tx80211_get_capabilities(input_tx) & TX80211_CAP_SETMODULATION) == 0) {
		snprintf(input_tx->errstr, TX80211_STATUS_MAX, "setmodulation: driver does not support setting  the modulation mechanism.");
		return TX80211_ENOTCAPAB;
	}
	input_packet->modulation = modulation;
	return TX80211_ENOERR;


int 
tx80211_getmodulation(input_packet) 
	TX80211_PACKET *input_packet
CODE:
	return(input_packet->modulation);


#//int 
#//tx80211_setfunctionalmode(input_tx, in_fmode)
#//	TX80211 *input_tx
#//	int in_fmode
#//PPCODE:
#	//if (input_tx->setfuncmode_callthrough == NULL)  {
#	//	snprintf(input_tx->errstr, TX80211_STATUS_MAX,  "Setfunctionalmode callthrough handler not implemented");
#	//	return TX80211_ENOHANDLER;
#	//}
#
#	//return (input_tx->setfuncmode_callthrough) (input_tx, in_fmode);


int 
tx80211_setchannel(input_tx, input_channel)
	TX80211 *input_tx
	int input_channel
CODE:
	if (input_tx->setchan_callthrough == NULL)
	{
		snprintf(input_tx->errstr, TX80211_STATUS_MAX,  "Setchannel callthrough handler not implemented");
		return TX80211_ENOHANDLER;
	}

	return (input_tx->setchan_callthrough) (input_tx, input_channel);


int 
tx80211_getchannel(input_tx)
	TX80211 *input_tx
CODE:
	if (input_tx->getchan_callthrough == NULL){
		snprintf(input_tx->errstr, TX80211_STATUS_MAX,  "Getchannel callthrough handler not implemented");
		return TX80211_ENOHANDLER;
	}
	return (input_tx->getchan_callthrough) (input_tx);

int 
tx80211_open(input_tx)
	TX80211 *input_tx
CODE:
	if (input_tx->open_callthrough == NULL){
		return TX80211_ENOHANDLER;
	}
	return (input_tx->open_callthrough);


int 
tx80211_close(input_tx)
	TX80211 *input_tx
CODE:
	if (input_tx->close_callthrough == NULL) {
		snprintf(input_tx->errstr, TX80211_STATUS_MAX,  "Close callthrough handler not implemented");
		return TX80211_ENOHANDLER;
	}

#define NL_STOP 00071

int 
nl80211_ack_cb(msg, arg) 
	NL_MSG *msg
	void *arg
CODE:
    int *ret = arg;
    *ret = 0;
    return NL_STOP;

int 
tx80211_selfack(in_tx, addr)
	TX80211 *in_tx
	uint8_t *addr

int 
tx80211_gettxrate(input_packet)
	TX80211_PACKET *input_packet
CODE:
	return(input_packet->txrate);
	
int 
tx80211_settxrate(input_tx, input_packet, txrate)
	TX80211 *input_tx
	TX80211_PACKET *input_packet
	int txrate
CODE:
	if (input_tx->injectortype == INJ_NODRIVER) {
		snprintf(input_tx->errstr, TX80211_STATUS_MAX, "settxrate: driver type not intialized");
		return TX80211_ENOINIT;
	}

	if ((tx80211_get_capabilities(input_tx) & TX80211_CAP_SETRATE) == 0) {
		snprintf(input_tx->errstr, TX80211_STATUS_MAX, "setmodulation: driver does not support setting the TX data rate.");
		return TX80211_ENOTCAPAB;
	}

	input_packet->txrate = txrate;
	return TX80211_ENOERR;

int 
tx80211_setfunctionalmode(input_tx, in_fmode)
	TX80211 *input_tx
	int in_fmode
CODE:	
	if (input_tx->setfuncmode_callthrough == NULL) 
	{
		snprintf(input_tx->errstr, TX80211_STATUS_MAX,  "Setfunctionalmode callthrough handler not implemented");
		return TX80211_ENOHANDLER;
	}

	return (input_tx->setfuncmode_callthrough);

int 
tx80211_getmode(input_tx)
	TX80211 *input_tx
CODE:
	if (input_tx->getmode_callthrough == NULL)
	{
		snprintf(input_tx->errstr, TX80211_STATUS_MAX,  "Getmode callthrough handler not implemented");
		return TX80211_ENOHANDLER;
	}

	return (input_tx->getmode_callthrough);

int 
tx80211_resolvecard(in_str)
	const char *in_str
	
int 
tx80211_resolveinterface(input_str)
	char *input_str
CODE:
#ifdef SYS_LINUX

	char driver[32];
	char *tmpdriver;

	tmpdriver = ifconfig_get_sysdriver(input_str);

	if (tmpdriver == NULL){
		return INJ_NODRIVER;
	}
	/* Clean up so we don't have to deal w/ it on each return */
	snprintf(driver, 32, "%s", tmpdriver);
	Safefree(tmpdriver);

	/* Check for the phy80211 attribute as a shortcut for detecting mac80211 devices */
	if (ifconfig_get_sysattr(input_str, "phy80211")){
		return INJ_MAC80211;
	}
	if (!strcasecmp(driver, "hostap")){
		return INJ_HOSTAP;
	}
	if (!strcasecmp(driver, "prism54")){
		return INJ_PRISM54;
	}
	if (!strcasecmp(driver, "madwifing") || !strcasecmp(driver, "madwifi-ng")){
		return INJ_MADWIFING;
	}
#endif

	return INJ_NODRIVER;
	
char *
tx80211_geterrstr(input_tx)
	TX80211 *input_tx
CODE:
	return newSVpv(input_tx->errstr, 0);

int 
tx80211_setmode(input_tx, input_mode)
	TX80211 *input_tx
	int input_mode
CODE:
	fprintf(stderr, "LORCON - tx80211_setmode(...) is deprecated, please use tx80211_setfunctionalmode(...) instead\n");

	if (input_tx->setmode_callthrough == NULL) 
	{
		snprintf(input_tx->errstr, TX80211_STATUS_MAX,  "Setmode callthrough handler not implemented");
		return TX80211_ENOHANDLER;
	}

	return (input_tx->setmode_callthrough);
	
TX80211 *
tx80211_meta()


int
tx80211_free(input_tx)
	TX80211 *input_tx
CODE:
	Safefree(input_tx);
	return 1;

TX80211_PACKET *
tx80211_packet_meta()


sha1_context *
sha1_meta()

sha1_hmac_context *
sha1_hmac_meta()
	
void
sha1_process(ctx, data)
    sha1_context *ctx
    uint8_t data

    
void 
sha1_update( ctx, input, length )
  sha1_context *ctx
  uint8_t *input
  uint32_t length
PPCODE:
    uint32_t left, fill;

    if( ! length ){
      return -1;
    }
    left = ctx->total[0] & 0x3F;
    fill = 64 - left;

    ctx->total[0] += length;
    ctx->total[0] &= 0xFFFFFFFF;

    if( ctx->total[0] < length )
        ctx->total[1]++;

    if( left && length >= fill ){
        //memcpy( (void *) (ctx->buffer + left), (const void *) input, fill );
        Copy(input, (ctx->buffer + left), fill, 1);
        sha1_process( ctx, ctx->buffer );
        length -= fill;
        input  += fill;
        left = 0;
    }

    while( length >= 64 ){
        sha1_process( ctx, input );
        length -= 64;
        input  += 64;
    }

    if( length ){
        //memcpy( (void *) (ctx->buffer + left), (const void *) input, length );
        Copy(input,  (ctx->buffer + left), length, 1);
    }
    
void 
sha1_finish( ctx, digest )
  sha1_context *ctx
  uint8_t digest

    
void 
sha1_hmac_starts( hctx, key, keylength )
    sha1_hmac_context *hctx
    uint8_t *key
    uint32_t keylength
CODE:
    uint32_t i;
    uint8_t k_ipad[64];    
    //memset( k_ipad, 0x36, 64 );
    Zero(k_ipad, 0x36, 64);
    //memset( hctx->k_opad, 0x5C, 64 );
    Zero(hctx->k_opad, 0x5C, 64);

    for( i = 0; i < keylength; i++ )
    {
        if( i >= 64 ) break;

        k_ipad[i] ^= key[i];
        hctx->k_opad[i] ^= key[i];
    }

    sha1_starts( &hctx->ctx );
    sha1_update( &hctx->ctx, k_ipad, 64 );


void 
sha1_hmac_update( hctx, buf, buflength )
    sha1_hmac_context *hctx
    uint8_t *buf
    uint32_t buflength
CODE:
    sha1_update( &hctx->ctx, buf, buflength );


void 
sha1_hmac_finish( hctx, digest )
    sha1_hmac_context *hctx
    uint8_t digest
CODE:
    uint8_t tmpbuf;
    sha1_finish( &hctx->ctx, tmpbuf );
    sha1_starts( &hctx->ctx );
    sha1_update( &hctx->ctx, hctx->k_opad, 64 );
    sha1_update( &hctx->ctx, tmpbuf, SHA1_DIGEST_LEN );
    sha1_finish( &hctx->ctx, digest );


void 
sha1_hmac( key, keylength, buf, buflength, digest )
    uint8_t *key
    uint32_t keylength
    uint8_t *buf
    uint32_t buflength
    uint8_t digest
CODE:
    sha1_hmac_context hctx;
    sha1_hmac_starts( &hctx, key, keylength );
    sha1_hmac_update( &hctx, buf, buflength );
    sha1_hmac_finish( &hctx, digest );

size_t
build_radio_tap_header(rt_header)
	void *rt_header
CODE:
	#define RADIOTAP_HEADER_LENGTH \
	"\x0c\0"
	#define RADIOTAP_HEADER_PRESENT_FLAGS \
	"\x04\x80\0\0" 
	#define RADIOTAP_HEADER_RATE_OPTION \
	"\0\0" 
	#define RADIOTAP_HEADER_LENGTH \
	"\x0a\0" 
	#define RADIOTAP_HEADER_PRESENT_FLAGS \
	"\x00\x80\0\0"
	#define RADIOTAP_HEADER_RATE_OPTION ""
	#define RADIOTAP_HEADER \
	"\0\0"  \
	RADIOTAP_HEADER_LENGTH \
	RADIOTAP_HEADER_PRESENT_FLAGS \
	RADIOTAP_HEADER_RATE_OPTION \
	"\x18\0" 
	int radio_header = sizeof(RADIOTAP_HEADER) - 1;
	//memcpy(rt_header, RADIOTAP_HEADER, sizeof(RADIOTAP_HEADER)-1);
	StructCopy(RADIOTAP_HEADER, rt_header, radio_header);
	RETVAL = ( sizeof(RADIOTAP_HEADER) - 1 );
OUTPUT:
	RETVAL
	
WPS_DATA *
get_wps()
CODE:
	GLOB *globule;
	return globule->wps;


uint16_t 
get_ap_capability()
CODE:
GLOB * globule;
RETVAL = globule->ap_capability;
OUTPUT:
RETVAL

void 
set_channel(channel)
int channel
CODE:
	GLOB *globule;
	globule->channel = channel;
        return( 0 );

int 
get_channel()
CODE:
	GLOB *globule;
	return globule->channel;

void 
set_bssid(value)
unsigned char *value
CODE:
	GLOB *globule;
	//memcpy(globule->bssid, value, MAC_ADDR_LEN);
	Copy(value, globule->bssid, MAC_ADDR_LEN, 1);
	return 0;

# define end_htole16(x) (uint16_t)(x)
#define LISTEN_INTERVAL         0x0064
#define OPEN_SYSTEM             0

size_t
build_association_management_frame(f)
         ASSOCIATION_REQUEST_MANAGEMENT_FRAME *f
CODE:
	
	f->capability = end_htole16(get_ap_capability());
	f->listen_interval = end_htole16(LISTEN_INTERVAL);
	return (sizeof *f);


size_t
build_authentication_management_frame(f)
         AUTH_MANAGEMENT_FRAME *f
CODE:

	f->algorithm = end_htole16(OPEN_SYSTEM);
	f->sequence = end_htole16(1);
	f->status = 0;
	return(sizeof *f);

void*
build_wps_probe_request(bssid, essid, length)
	unsigned char *bssid
	char *essid
	size_t *length
CODE:	
	TAG_PARAMS *ssid_tag;
	void *packet = NULL;
	size_t offset = 0, rt_len = 0, dot11_len = 0, ssid_tag_len = 0, packet_len = 0;
	int broadcast = !memcmp(bssid, "\xff\xff\xff\xff\xff\xff", 6);

	if(!broadcast && essid != NULL)
	{
		 ssid_tag->len = (uint8_t) strlen(essid);
	}
	else
	{
		ssid_tag->len = 0;
	}

	#define SSID_TAG_NUMBER 0

	ssid_tag->number = SSID_TAG_NUMBER;
	ssid_tag_len = ssid_tag->len + sizeof(TAG_PARAMS *);
	struct radio_tap_header *rt_header;
	rt_len = build_radio_tap_header(&rt_header);
	DOT_11_FRAME_H *dot11_header;
	dot11_len = build_dot11_frame_header_m(&dot11_header, FC_PROBE_REQUEST, bssid);

	packet_len = rt_len + dot11_len + ssid_tag_len;
	return 0;

void *
build_snap_packet(length)
	size_t *length
CODE:
	void *packet = NULL;
	size_t rt_len = 0, dot11_len = 0, llc_len = 0, packet_len = 0;
	struct radio_tap_header rt_header;
	struct dot11_frame_header dot11_header;
	struct llc_header llc_header;
	rt_len = build_radio_tap_header(&rt_header);
        dot11_len = build_dot11_frame_header(&dot11_header, FC_STANDARD);
        llc_len = build_llc_header(&llc_header);

	packet_len = rt_len + dot11_len + llc_len;
	//packet = malloc(packet_len);
	Newx(packet, packet_len, 1);
	if(packet) {
		//memset((void *) packet, 0, packet_len);
		Zero(packet, 0, packet_len);
		//memcpy((void *) packet, &rt_header, rt_len);
		Copy(&rt_header, packet, rt_len, 1);
		//memcpy((void *) ((char *) packet+rt_len), &dot11_header, dot11_len);
		char *p = packet + rt_len;
		Copy(&dot11_header, p, dot11_len, 1);
		//memcpy((void *) ((char *) packet+rt_len+dot11_len), &llc_header, llc_len);
		char *p1 = packet + rt_len + dot11_len;
		Copy(&llc_header, p1, llc_len, 1);
		*len = packet_len;
	}
	return packet;

void *
build_eap_packet(payload, payload_length, length)
	const void *payload
	uint16_t payload_length
	size_t *length
CODE:
	void *buf = NULL, *snap_packet = NULL, *eap_header = NULL, *dot1x_header = NULL, *wfa_header = NULL;
	size_t buf_len = 0, snap_len = 0, eap_len = 0, dot1x_len = 0, wfa_len = 0, offset = 0, total_payload_len = 0;
	uint8_t eap_type = 0, eap_code = 0;
	WPS_DATA *wps = get_wps();

	switch(wps->state)
	{
		case RECV_M1:
			eap_code = EAP_RESPONSE;
			eap_type = EAP_IDENTITY;
			break;
		default:
			eap_code = EAP_RESPONSE;
			eap_type = EAP_EXPANDED;
	}
	total_payload_len = payload_length;
	if(eap_type == EAP_EXPANDED)
	{
		wfa_header = build_wfa_header(get_opcode(), &wfa_len);
		total_payload_len += wfa_len;
	}

	snap_packet = build_snap_packet(&snap_len);
	eap_header = build_eap_header(get_eap_id(), eap_code, eap_type, total_payload_len, &eap_len);
	dot1x_header = build_dot1X_header(DOT1X_EAP_PACKET, (total_payload_len+eap_len), &dot1x_len);
	if(snap_packet && eap_header && dot1x_header)
	{
		buf_len = snap_len + dot1x_len + eap_len + total_payload_len;
		buf = malloc(buf_len);
		if(buf)
		{
			//memset((void *) buf, 0, buf_len);
			Zero(buf, 1, buf_len);
			//memcpy((void *) buf, snap_packet, snap_len);
			Copy(snap_packet, buf, snap_len, 1);
			offset += snap_len;
			//memcpy((void *) ((char *) buf+offset), dot1x_header, dot1x_len);
			char *boffset =  buf + offset;
			Copy(dot1x_header, boffset, dot1x_len, 1);
			offset += dot1x_len;
			//memcpy((void *) ((char *) buf+offset), eap_header, eap_len);
			Copy(eap_header, boffset, eap_len, 1);
			offset += eap_len;
	
			if(eap_type == EAP_EXPANDED)
			{
				//memcpy((void *) ((char *) buf+offset), wfa_header, wfa_len);
				Copy(wfa_header, boffset, wfa_len, 1);
				offset += wfa_len;
			}

			if(payload && payload_length)
			{
				//memcpy((void *) ((char *) buf+offset), payload, payload_length);
				Copy(payload, boffset, payload_length, 1);
			}
			int *len;
			*len = (offset + payload_length);
		}

		Safefree(snap_packet);
		Safefree(eap_header);
		Safefree(dot1x_header);
		if(wfa_header) {
			Safefree((void *) wfa_header);
	}
	}	
}
		return(buf);

ASSOCIATION_REQUEST_MANAGEMENT_FRAME *
assoc_request_meta()

ASSOCIATION_RESP_MANAGEMENT_FRAME *
assoc_response_meta()

BEACON_MANAGEMENT_FRAME *
beacon_management_meta()

AUTH_MANAGEMENT_FRAME *
auth_management_meta()
