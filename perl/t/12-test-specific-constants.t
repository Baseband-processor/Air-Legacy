#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
# easy test which takes 100 random functions and tests if returns some value

use strict;
use strict 'subs';
no warnings;
use Test;

BEGIN{ plan tests => 152 };
use Air::Lorcon2 qw( :suites :ieee802_11 :network_const  :tx_80211  :wifi_mask :requests  :radiotap  :status :rate :extrapacket :channel :consts  );

my @Lorcon_Costants = qw(
      WEP_CRC_TABLE
      LORCON_EGENERIC
      LORCON_ENOTSUPP
      LORCON_STATUS_MAX
      LORCON_MAX_PACKET_LEN
      LORCON_RTAP_CHAN_TURBO
      LORCON_RTAP_CHAN_CCK
      LORCON_RTAP_CHAN_OFDM
      LORCON_RTAP_CHAN_2GHZ
      LORCON_RTAP_CHAN_5GHZ
      LORCON_RTAP_CHAN_PASSIVE
      LORCON_RTAP_CHAN_DYN
      LORCON_RTAP_CHAN_GFSK
      LORCON_RTAP_CHAN_STURBO
  	  TX_IEEE80211_RADIOTAP_TSFT 
	  TX_IEEE80211_RADIOTAP_FLAGS
	  TX_IEEE80211_RADIOTAP_RATE 
	  TX_IEEE80211_RADIOTAP_CHANNEL
	  TX_IEEE80211_RADIOTAP_FHSS
	  TX_IEEE80211_RADIOTAP_DBM_ANTSIGNAL
	  TX_IEEE80211_RADIOTAP_DBM_ANTNOISE 
	  TX_IEEE80211_RADIOTAP_LOCK_QUALITY 
	  TX_IEEE80211_RADIOTAP_TX_ATTENUATION
	  TX_IEEE80211_RADIOTAP_DB_TX_ATTENUATION 
	  TX_IEEE80211_RADIOTAP_DBM_TX_POWER 
	  TX_IEEE80211_RADIOTAP_ANTENNA 
	  TX_IEEE80211_RADIOTAP_DB_ANTSIGNAL 
	  TX_IEEE80211_RADIOTAP_DB_ANTNOISE 
	  TX_IEEE80211_RADIOTAP_FCS 
	  TX_IEEE80211_RADIOTAP_EXT 
  	IF_GET_IFACE
	IF_GET_PROTO
	IF_IFACE_V35
	IF_IFACE_V24
	IF_IFACE_X21
	IF_IFACE_T1
	IF_IFACE_E1
	IF_IFACE_SYNC_SERIAL
	IF_IFACE_X21D
	IF_PROTO_HDLC
	IF_PROTO_PPP
	IF_PROTO_CISCO
	IF_PROTO_FR
	IF_PROTO_FR_ADD_PVC
	IF_PROTO_FR_DEL_PVC
	IF_PROTO_X25
	IF_PROTO_HDLC_ETH
	IF_PROTO_FR_ADD_ETH_PVC
	IF_PROTO_FR_DEL_ETH_PVC
	IF_PROTO_FR_PVC	
	IF_PROTO_FR_ETH_PVC
	IF_PROTO_RAW
	ICMP_ECHOREPLY
	ICMP_DEST_UNREACH
	ICMP_SOURCE_QUENCH
	ICMP_REDIRECT
	ICMP_ECHO
	ICMP_TIME_EXCEEDED
	ICMP_PARAMETERPROB
	ICMP_TIMESTAMP
	ICMP_TIMESTAMPREPLY
	ICMP_INFO_REQUEST
	ICMP_INFO_REPLY
	ICMP_ADDRESS
	ICMP_ADDRESSREPLY
	NR_ICMP_TYPES
	ICMP_NET_UNREACH
	ICMP_HOST_UNREACH
	ICMP_PROT_UNREACH
	ICMP_PORT_UNREACH
	ICMP_FRAG_NEEDED	
	ICMP_SR_FAILED
	ICMP_NET_UNKNOWN
	ICMP_HOST_UNKNOWN
	ICMP_HOST_ISOLATED	
	ICMP_NET_ANO
	ICMP_HOST_ANO
	ICMP_NET_UNR_TOS
	ICMP_HOST_UNR_TOS
	ICMP_PKT_FILTERED
	ICMP_PREC_VIOLATION
	ICMP_PREC_CUTOFF
	NR_ICMP_UNREACH
	ICMP_REDIR_NET
	ICMP_REDIR_HOST
	ICMP_REDIR_NETTOS
	ICMP_REDIR_HOSTTOS
	ICMP_EXC_TTL
	ICMP_EXC_FRAGTIME
	TCP_MSS_DEFAULT
	TCP_MSS_DESIRED
	TCP_NODELAY
	TCP_MAXSEG
	TCP_CORK
	TCP_KEEPIDLE
	TCP_KEEPINTVL
	TCP_KEEPCNT
	TCP_SYNCNT
	TCP_LINGER2
	TCP_DEFER_ACCEPT
	TCP_WINDOW_CLAMP
	TCP_INFO
	TCP_QUICKACK
	TCP_CONGESTION
	TCP_MD5SIG
	TCP_THIN_LINEAR_TIMEOUTS
	TCP_THIN_DUPACK
	TCP_USER_TIMEOUT
	TCP_REPAIR
	TCP_REPAIR_QUEUE
	TCP_QUEUE_SEQ
	TCP_REPAIR_OPTIONS
	TCP_FASTOPEN
	TCP_TIMESTAMP
	TCP_NOTSENT_LOWAT
	TCP_CC_INFO
	TCP_SAVE_SYN
	TCP_SAVED_SYN
	UDP_CORK
	UDP_ENCAP
	UDP_NO_CHECK6_TX
	UDP_NO_CHECK6_RX
	UDP_ENCAP_ESPINUDP_NON_IKE
	UDP_ENCAP_ESPINUDP
	UDP_ENCAP_L2TPINUDP
	IPTOS_TOS_MASK
	IPTOS_LOWDELAY
	IPTOS_THROUGHPUT
	IPTOS_RELIABILITY
	IPTOS_MINCOST
	IPTOS_PREC_MASK
	IPTOS_PREC_NETCONTROL
	IPTOS_PREC_INTERNETCONTROL
	IPTOS_PREC_CRITIC_ECP
	IPTOS_PREC_FLASHOVERRIDE
	IPTOS_PREC_FLASH
	IPTOS_PREC_IMMEDIATE
	IPTOS_PREC_PRIORITY
	IPTOS_PREC_ROUTINE
	IPOPT_COPY
	IPOPT_CLASS_MASK
	IPOPT_NUMBER_MASK
	IPOPT_COPY
	IPOPT_CLASS_MASK
	IPOPT_NUMBER_MASK
	IPOPT_CONTROL
	IPOPT_RESERVED1
	IPOPT_MEASUREMENT
	IPOPT_RESERVED2
	IPVERSION
	MAXTTL
	IPDEFTTL
	IPOPT_OPTVAL
	IPOPT_OLEN
	IPOPT_OFFSET
	IPOPT_MINOFF
	MAX_IPOPTLEN
	IPOPT_NOP
	IPOPT_EOL
	IPOPT_TS
	IPOPT_TS_TSONLY
	IPOPT_TS_TSANDADDR
	IPOPT_TS_PRESPEC
	IPV4_BEET_PHMAXLEN
	IPV6_TLV_TNL_ENCAP_LIMIT
	IPV6_DEFAULT_TNL_ENCAP_LIMIT
	IP6_TNL_F_IGN_ENCAP_LIMIT
	IP6_TNL_F_USE_ORIG_TCLASS
	IP6_TNL_F_USE_ORIG_FLOWLABEL
	IP6_TNL_F_MIP6_DEV
	IP6_TNL_F_RCV_DSCP_COPY
	IP6_TNL_F_USE_ORIG_FWMARK
	IPV6_SRCRT_STRICT
	IPV6_SRCRT_TYPE_0
	IPV6_SRCRT_TYPE_2
	IPV6_OPT_ROUTERALERT_MLD
	RTF_DEFAULT
	RTF_ALLONLINK
	RTF_ADDRCONF
	RTF_PREFIX_RT
	RTF_ANYCAST
	RTF_NONEXTHOP
	RTF_EXPIRES
	RTF_ROUTEINFO
	RTF_CACHE
	RTF_FLOW
	RTF_POLICY
	RTF_PREF_MASK
	RTF_PCPU
	RTF_LOCAL
	RTMSG_NEWDEVICE
	RTMSG_DELDEVICE
	RTMSG_NEWROUTE
	RTMSG_DELROUTE
	IP6_RT_PRIO_USER
	IP6_RT_PRIO_ADDRCONF
      WLAN_STATUS_SUCCESS                     
      WLAN_STATUS_UNSPECIFIED_FAILURE         
      WLAN_STATUS_CAPS_UNSUPPORTED            
      WLAN_STATUS_REASSOC_NO_ASSOC            
      WLAN_STATUS_ASSOC_DENIED_UNSPEC         
      WLAN_STATUS_NOT_SUPPORTED_AUTH_ALG      
      WLAN_STATUS_UNKNOWN_AUTH_TRANSACTION    
      WLAN_STATUS_CHALLENGE_FAIL              
      WLAN_STATUS_AUTH_TIMEOUT                
      WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA 
      WLAN_STATUS_ASSOC_DENIED_RATES          
      WLAN_STATUS_ASSOC_DENIED_NOSHORT        
      WLAN_STATUS_ASSOC_DENIED_NOPBCC         
      WLAN_STATUS_ASSOC_DENIED_NOAGILITY      
      WLAN_STATUS_INVALID_IE                  
      WLAN_STATUS_GROUP_CIPHER_NOT_VALID      
      WLAN_STATUS_PAIRWISE_CIPHER_NOT_VALID   
      WLAN_STATUS_AKMP_NOT_VALID              
      WLAN_STATUS_UNSUPPORTED_RSN_IE_VERSION  
      WLAN_STATUS_INVALID_RSN_IE_CAPAB        
      WLAN_STATUS_CIPHER_REJECTED_PER_POLICY  
     WLAN_FC_SUBTYPE_ASSOCREQ    
     WLAN_FC_SUBTYPE_ASSOCRESP   
     WLAN_FC_SUBTYPE_REASSOCREQ  
     WLAN_FC_SUBTYPE_REASSOCRESP 
     WLAN_FC_SUBTYPE_PROBEREQ    
     WLAN_FC_SUBTYPE_PROBERESP   
     WLAN_FC_SUBTYPE_BEACON      
     WLAN_FC_SUBTYPE_ATIM        
     WLAN_FC_SUBTYPE_DISASSOC    
     WLAN_FC_SUBTYPE_AUTH        
     WLAN_FC_SUBTYPE_DEAUTH      
      LORCON_RATE_DEFAULT     
      LORCON_RATE_1MB               
      LORCON_RATE_2MB               
      LORCON_RATE_5_5MB            
      LORCON_RATE_6MB              
      LORCON_RATE_9MB              
      LORCON_RATE_11MB              
      LORCON_RATE_12MB              
      LORCON_RATE_18MB              
      LORCON_RATE_24MB              
      LORCON_RATE_36MB              
      LORCON_RATE_48MB              
      LORCON_RATE_54MB             
      LORCON_RATE_108MB       
  LORCON_PACKET_EXTRA_NONE
  LORCON_PACKET_EXTRA_80211         
  LORCON_PACKET_EXTRA_8023        
 	IEEE80211_MIN_AMPDU_BUF
	IEEE80211_MAX_AMPDU_BUF
	IEEE80211_HT_PARAM_CHA_SEC_OFFSET
	IEEE80211_HT_PARAM_CHA_SEC_NONE
	IEEE80211_HT_PARAM_CHA_SEC_ABOVE
	IEEE80211_HT_PARAM_CHA_SEC_BELOW
	IEEE80211_HT_PARAM_CHAN_WIDTH_ANY
	IEEE80211_HT_PARAM_RIFS_MODE
	IEEE80211_HT_OP_MODE_PROTECTION
	IEEE80211_HT_OP_MODE_PROTECTION_NONE
	IEEE80211_HT_OP_MODE_PROTECTION_NONMEMBER
	IEEE80211_HT_OP_MODE_PROTECTION_20MHZ
	IEEE80211_HT_OP_MODE_PROTECTION_NONHT_MIXED
	IEEE80211_HT_OP_MODE_NON_GF_STA_PRSNT
	IEEE80211_HT_OP_MODE_NON_HT_STA_PRSNT
	IEEE80211_HT_OP_MODE_CCFS2_SHIFT
	IEEE80211_HT_OP_MODE_CCFS2_MASK
	IEEE80211_HT_STBC_PARAM_DUAL_BEACON
	IEEE80211_HT_STBC_PARAM_DUAL_CTS_PROT
	IEEE80211_HT_STBC_PARAM_STBC_BEACON
	IEEE80211_HT_STBC_PARAM_LSIG_TXOP_FULLPROT
	IEEE80211_HT_STBC_PARAM_PCO_ACTIVE
	IEEE80211_HT_STBC_PARAM_PCO_PHASE
	IEEE80211_ADDBA_PARAM_AMSDU_MASK
	IEEE80211_ADDBA_PARAM_POLICY_MASK
	IEEE80211_ADDBA_PARAM_TID_MASK
	IEEE80211_ADDBA_PARAM_BUF_SIZE_MASK
	IEEE80211_DELBA_PARAM_TID_MASK
	IEEE80211_DELBA_PARAM_INITIATOR_MASK
	IEEE80211_HT_CAP_LDPC_CODING
	IEEE80211_HT_CAP_SUP_WIDTH_20_40
	IEEE80211_HT_CAP_SM_PS
	IEEE80211_HT_CAP_SM_PS_SHIFT
	IEEE80211_HT_CAP_GRN_FLD
	IEEE80211_HT_CAP_SGI_20
	IEEE80211_HT_CAP_SGI_40
	IEEE80211_HT_CAP_TX_STBC
	IEEE80211_HT_CAP_RX_STBC
	IEEE80211_HT_CAP_RX_STBC_SHIFT
	IEEE80211_HT_CAP_DELAY_BA
	IEEE80211_HT_CAP_MAX_AMSDU
	IEEE80211_HT_CAP_DSSSCCK40
	IEEE80211_HT_CAP_RESERVED
	IEEE80211_HT_CAP_40MHZ_INTOLERANT
	IEEE80211_HT_CAP_LSIG_TXOP_PROT
	IEEE80211_HT_EXT_CAP_PCO
	IEEE80211_HT_EXT_CAP_PCO_TIME
	IEEE80211_HT_EXT_CAP_PCO_TIME_SHIFT
	IEEE80211_HT_EXT_CAP_MCS_FB
	IEEE80211_HT_EXT_CAP_MCS_FB_SHIFT
	IEEE80211_HT_EXT_CAP_HTC_SUP
	IEEE80211_HT_EXT_CAP_RD_RESPONDER
	IEEE80211_FCTL_VERS
	IEEE80211_FCTL_FTYPE
	IEEE80211_FCTL_STYPE
	IEEE80211_FCTL_TODS
	IEEE80211_FCTL_FROMDS
	IEEE80211_FCTL_MOREFRAGS
	IEEE80211_FCTL_RETRY
	IEEE80211_FCTL_PM
	IEEE80211_FCTL_MOREDATA
	IEEE80211_FCTL_PROTECTED
	IEEE80211_FCTL_ORDER
	IEEE80211_FCTL_CTL_EXT
	IEEE80211_SCTL_FRAG
	IEEE80211_SCTL_SEQ
	IEEE80211_FTYPE_MGMT
	IEEE80211_FTYPE_CTL
	IEEE80211_FTYPE_DATA
	IEEE80211_FTYPE_EXT
	IEEE80211_STYPE_ASSOC_REQ
	IEEE80211_STYPE_ASSOC_RESP
	IEEE80211_STYPE_REASSOC_REQ
	IEEE80211_STYPE_REASSOC_RESP
	IEEE80211_STYPE_PROBE_REQ
	IEEE80211_STYPE_PROBE_RESP
	IEEE80211_STYPE_BEACON
	IEEE80211_STYPE_ATIM
	IEEE80211_STYPE_DISASSOC
	IEEE80211_STYPE_AUTH
	IEEE80211_STYPE_DEAUTH
	IEEE80211_STYPE_ACTION
	IEEE80211_STYPE_CTL_EXT
	IEEE80211_STYPE_BACK_REQ
	IEEE80211_STYPE_BACK
	IEEE80211_STYPE_PSPOLL
	IEEE80211_STYPE_RTS
	IEEE80211_STYPE_CTS
	IEEE80211_STYPE_ACK
	IEEE80211_STYPE_CFEND
	IEEE80211_STYPE_CFENDACK
	IEEE80211_STYPE_DATA
	IEEE80211_STYPE_DATA_CFACK
	IEEE80211_STYPE_DATA_CFPOLL
	IEEE80211_STYPE_DATA_CFACKPOLL
	IEEE80211_STYPE_NULLFUNC
	IEEE80211_STYPE_CFACK
	IEEE80211_STYPE_CFPOLL
	IEEE80211_STYPE_CFACKPOLL
	IEEE80211_STYPE_QOS_DATA
	IEEE80211_STYPE_QOS_DATA_CFACK
	IEEE80211_STYPE_QOS_DATA_CFPOLL
	IEEE80211_STYPE_QOS_DATA_CFACKPOLL
	IEEE80211_STYPE_QOS_NULLFUNC
	IEEE80211_STYPE_QOS_CFACK
	IEEE80211_STYPE_QOS_CFPOLL
	IEEE80211_STYPE_QOS_CFACKPOLL
	IEEE80211_STYPE_DMG_BEACON
	IEEE80211_CTL_EXT_POLL
	IEEE80211_CTL_EXT_SPR
	IEEE80211_CTL_EXT_GRANT
	IEEE80211_CTL_EXT_DMG_CTS
	IEEE80211_CTL_EXT_DMG_DTS
	IEEE80211_CTL_EXT_SSW
	IEEE80211_CTL_EXT_SSW_FBACK
	IEEE80211_CTL_EXT_SSW_ACK
	WLAN_MAX_KEY_LEN
	WLAN_PMK_NAME_LEN
	WLAN_PMKID_LEN
	WLAN_PMK_LEN_EAP_LEAP
	WLAN_PMK_LEN
	WLAN_PMK_LEN_SUITE_B_192
	WLAN_OUI_WFA
	WLAN_OUI_TYPE_WFA_P2P
	WLAN_OUI_MICROSOFT
	WLAN_OUI_TYPE_MICROSOFT_WPA
	WLAN_OUI_TYPE_MICROSOFT_WMM
	WLAN_OUI_TYPE_MICROSOFT_WPS
	WLAN_OUI_TYPE_MICROSOFT_TPC
	IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_3895
	IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_7991
	IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_11454
	IEEE80211_VHT_CAP_MAX_MPDU_MASK
	IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160MHZ
	IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160_80PLUS80MHZ
	IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_MASK
	IEEE80211_VHT_CAP_RXLDPC
	IEEE80211_VHT_CAP_SHORT_GI_80
	IEEE80211_VHT_CAP_SHORT_GI_160
	IEEE80211_VHT_CAP_TXSTBC
	IEEE80211_VHT_CAP_RXSTBC_1
	IEEE80211_VHT_CAP_RXSTBC_2
	IEEE80211_VHT_CAP_RXSTBC_3
	IEEE80211_VHT_CAP_RXSTBC_4
	IEEE80211_VHT_CAP_RXSTBC_MASK
	IEEE80211_VHT_CAP_SU_BEAMFORMER_CAPABLE
	IEEE80211_VHT_CAP_SU_BEAMFORMEE_CAPABLE
	IEEE80211_VHT_CAP_BEAMFORMEE_STS_SHIFT
	IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_SHIFT
	IEEE80211_VHT_CAP_MU_BEAMFORMER_CAPABLE
	IEEE80211_VHT_CAP_MU_BEAMFORMEE_CAPABLE
	IEEE80211_VHT_CAP_VHT_TXOP_PS
	IEEE80211_VHT_CAP_HTC_VHT
	IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT
	IEEE80211_VHT_CAP_VHT_LINK_ADAPTATION_VHT_UNSOL_MFB
	IEEE80211_VHT_CAP_VHT_LINK_ADAPTATION_VHT_MRQ_MFB
	IEEE80211_VHT_CAP_RX_ANTENNA_PATTERN
	IEEE80211_VHT_CAP_TX_ANTENNA_PATTERN
      LORCON_CHANNEL_BASIC
      LORCON_CHANNEL_HT20
      LORCON_CHANNEL_HT40P
      LORCON_CHANNEL_HT40M
      LORCON_CHANNEL_5MHZ
      LORCON_CHANNEL_10MHZ
      LORCON_CHANNEL_VHT80
      LORCON_CHANNEL_VHT160
      LORCON_CHANNEL_VHT8080
      WIFI_WIDTH_MASK 
      WIFI_HT_MASK 
      WIFI_OTHER_MASK 
      WEP40
       WEP104
       CCMP
       TKIP
       EAP
       PSK
);

my $consts_cardinality = $#Lorcon_Costants;
my $Rand_value = rand( $consts_cardinality ); # set the maximun random number the Costants array dimension
my $x = 0;
while( $x <= 150 ) {
  if( ! undef( $Lorcon_Costants[$Rand_value] ) ){
      ok(1);
  }else{
      ok(0);
   }
  $Rand_value; # refresh random value
  $x++;
}

ok(1);
