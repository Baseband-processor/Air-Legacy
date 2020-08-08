package Net::Lorcon2;
require  v5.22.1;

use strict;
use warnings;

our $VERSION = '4.00';
use base qw(Exporter DynaLoader);

use constant LORCON_EGENERIC => -1;
use constant LORCON_ENOTSUPP => -255;
use constant LORCON_STATUS_MAX => 1024;
use constant LORCON_MAX_PACKET_LEN => 8192;
use constant LORCON_CHANNEL_BASIC => 0;
use constant LORCON_CHANNEL_HT20 => 1;
use constant LORCON_CHANNEL_HT40P => 2;
use constant LORCON_CHANNEL_HT40M => 3;
use constant LORCON_CHANNEL_5MHZ =>  4;
use constant LORCON_CHANNEL_10MHZ => 5;
use constant LORCON_CHANNEL_VHT80 => 6;
use constant LORCON_CHANNEL_VHT160 => 7;
use constant LORCON_CHANNEL_VHT8080 => 8;  

use constant LORCON_RTAP_CHAN_TURBO => 0x0010;   
use constant LORCON_RTAP_CHAN_CCK  =>  0x0020;   
use constant LORCON_RTAP_CHAN_OFDM =>  0x0040; 
use constant LORCON_RTAP_CHAN_2GHZ =>  0x0080;
use constant LORCON_RTAP_CHAN_5GHZ =>  0x0100;
use constant LORCON_RTAP_CHAN_PASSIVE => 0x0200;
use constant LORCON_RTAP_CHAN_DYN => 0x0400;
use constant LORCON_RTAP_CHAN_GFSK => 0x0800;
use constant LORCON_RTAP_CHAN_STURBO => 0x2000;

use constant LORCON_RATE_DEFAULT => 0;
use constant LORCON_RATE_1MB => 2; 
use constant LORCON_RATE_2MB => 4; 
use constant LORCON_RATE_5_5MB => 11;
use constant LORCON_RATE_6MB => 12;
use constant LORCON_RATE_9MB => 18;
use constant LORCON_RATE_11MB => 22; 
use constant LORCON_RATE_12MB => 24; 
use constant LORCON_RATE_18MB => 36; 
use constant LORCON_RATE_24MB => 48; 
use constant LORCON_RATE_36MB => 72; 
use constant LORCON_RATE_48MB => 96; 
use constant LORCON_RATE_54MB => 108;
use constant LORCON_RATE_108MB => 216;

use constant LORCON_PACKET_EXTRA_NONE => 0;
use constant LORCON_PACKET_EXTRA_80211 => 1;
use constant LORCON_PACKET_EXTRA_8023 => 2;

use constant WLAN_STATUS_SUCCESS => 0;
use constant WLAN_STATUS_UNSPECIFIED_FAILURE => 1;
use constant WLAN_STATUS_CAPS_UNSUPPORTED => 10;
use constant WLAN_STATUS_REASSOC_NO_ASSOC => 11;
use constant WLAN_STATUS_ASSOC_DENIED_UNSPEC => 12;
use constant WLAN_STATUS_NOT_SUPPORTED_AUTH_ALG => 13;
use constant WLAN_STATUS_UNKNOWN_AUTH_TRANSACTION => 14;
use constant WLAN_STATUS_CHALLENGE_FAIL => 15;
use constant WLAN_STATUS_AUTH_TIMEOUT => 16;
use constant WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA => 17;
use constant WLAN_STATUS_ASSOC_DENIED_RATES => 18;
use constant WLAN_STATUS_ASSOC_DENIED_NOSHORT => 19;
use constant WLAN_STATUS_ASSOC_DENIED_NOPBCC => 20;
use constant WLAN_STATUS_ASSOC_DENIED_NOAGILITY => 21;
use constant WLAN_STATUS_INVALID_IE => 40;
use constant WLAN_STATUS_GROUP_CIPHER_NOT_VALID => 41;
use constant WLAN_STATUS_PAIRWISE_CIPHER_NOT_VALID => 42;
use constant WLAN_STATUS_AKMP_NOT_VALID => 43;
use constant WLAN_STATUS_UNSUPPORTED_RSN_IE_VERSION => 44;
use constant WLAN_STATUS_INVALID_RSN_IE_CAPAB => 45;
use constant WLAN_STATUS_CIPHER_REJECTED_PER_POLICY => 46;

use constant WLAN_FC_SUBTYPE_ASSOCREQ => 0;
use constant WLAN_FC_SUBTYPE_ASSOCRESP => 1;
use constant WLAN_FC_SUBTYPE_REASSOCREQ => 2;
use constant WLAN_FC_SUBTYPE_REASSOCRESP => 3;
use constant WLAN_FC_SUBTYPE_PROBEREQ => 4;
use constant WLAN_FC_SUBTYPE_PROBERESP => 5;
use constant WLAN_FC_SUBTYPE_BEACON => 8;
use constant WLAN_FC_SUBTYPE_ATIM =>  9;
use constant WLAN_FC_SUBTYPE_DISASSOC => 10;
use constant WLAN_FC_SUBTYPE_AUTH => 11;
use constant WLAN_FC_SUBTYPE_DEAUTH => 12;

# status and requests tags are from ie80211 file 

our %EXPORT_TAGS = (
   consts => [qw(
      LORCON_EGENERIC
      LORCON_ENOTSUPP
      LORCON_STATUS_MAX
      LORCON_MAX_PACKET_LEN
   )],
  radiotap => [qw(
      LORCON_RTAP_CHAN_TURBO
      LORCON_RTAP_CHAN_CCK
      LORCON_RTAP_CHAN_OFDM
      LORCON_RTAP_CHAN_2GHZ
      LORCON_RTAP_CHAN_5GHZ
      LORCON_RTAP_CHAN_PASSIVE
      LORCON_RTAP_CHAN_DYN
      LORCON_RTAP_CHAN_GFSK
      LORCON_RTAP_CHAN_STURBO
)],
  
  status => [qw(
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
)],
  requests => [qw(
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

)],

  rate => [qw(
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

)],

  extrapacket => [qw(
  LORCON_PACKET_EXTRA_NONE
  LORCON_PACKET_EXTRA_80211         
  LORCON_PACKET_EXTRA_8023        
)],

  channel => [qw(
      LORCON_CHANNEL_BASIC
      LORCON_CHANNEL_HT20
      LORCON_CHANNEL_HT40P
      LORCON_CHANNEL_HT40M
      LORCON_CHANNEL_5MHZ
      LORCON_CHANNEL_10MHZ
      LORCON_CHANNEL_VHT80
      LORCON_CHANNEL_VHT160
      LORCON_CHANNEL_VHT8080

)],

   lorcon => [qw(
      lorcon_list_drivers
      lorcon_find_driver
      lorcon_set_datalink
      lorcon_get_datalink
      lorcon_create
      lorcon_free_driver_list
      lorcon_free
      lorcon_set_timeout
      lorcon_get_timeout
      lorcon_open_monitor
      lorcon_open_injmon
      lorcon_set_vap
      lorcon_get_vap
      lorcon_get_capiface
      lorcon_auto_driver
      lorcon_get_driver_name
      lorcon_get_error
      lorcon_open_inject
      lorcon_send_bytes
      lorcon_get_useraux
      lorcon_set_useraux
      lorcon_packet_free
      lorcon_packet_decode
      lorcon_packet_set_channel
      lorcon_packet_get_channel
      lorcon_loop 
      lorcon_packet_to_dot3
      lorcon_set_hwmac
      lorcon_get_hwmac
      lorcon_multi_remove_interface_error_handler
      lorcon_multi_interface_get_lorcon
      lorcon_multi_get_next_interface
      lorcon_multi_get_interfaces
      lorcon_multi_del_interface
      lorcon_multi_add_interface
      lorcon_multi_free
      lorcon_multi_create
      lorcon_get_complex_channel 
      lorcon_set_complex_channel
      lorcon_ifdown
      locon_packet_get_bssid_mac
      lorcon_packet_get_dest_mac
      lcpf_randmac
      lorcon_packet_get_source_mac
      lorcon_ifup
      lorcon_packet_from_dot3
      lorcon_packet_to_dot3
      lorcon_breakloop
      lorcon_set_filter
      lorcon_next_ex
      lorcon_parse_ht_channel
      lorcon_get_selectable_fd
      lorcon_packet_set_freedata
      lorcon_get_pcap
      drv_madwifing_init
      drv_madwifing_listdriver
      lorcon_close
      lorcon_inject
      lorcon_add_wepkey
      aj_recvframe
      aj_xmitframe
      aj_setmac
      aj_setchannel
      aj_setmode
      aj_setmonitor
      lorcon_airjack_listdriver
      lorcon_airjack_init
      iwconfig_set_mode
      iwconfig_get_mode
      iwconfig_set_channel
      iwconfig_get_channel
      iwconfig_get_name
      iwconfig_get_ssid
      iwconfig_set_ssid
      nl80211_find_parent
      nl80211_setfrequency_cache
      nl80211_setfrequency
      nl80211_setchannel
      nl80211_setchannel_cache
      nl80211_createvif
      nl80211_disconnect
      nl80211_connect
      airpcap_setmode
      airpcap_close
      airpcap_setfuncmode
      airpcap_send
      airpcap_open
      tx80211_airpcap_capabilities
      tx80211_airpcap_init 
      drv_file_listdriver
      drv_rtfile_init
      drv_file_init
      drv_tuntap_listdriver
      drv_tuntap_init
      tx80211_hostap_capabilities
      tx80211_hostap_init
      drv_mac80211_listdriver
      drv_mac80211_init
      RMAC_gen
      RString_Gen
      Craft_TCP_Frame
      Craft_UDP_Frame
      Craft_RAW_Frame
      Craft_NULL_Frame
   )],
);

our @EXPORT = (
   @{ $EXPORT_TAGS{consts} },
   @{ $EXPORT_TAGS{lorcon} },
   @{ $EXPORT_TAGS{channel} },
   @{ $EXPORT_TAGS{extrapacket} },
   @{ $EXPORT_TAGS{rate} },
   @{ $EXPORT_TAGS{status} },
   @{ $EXPORT_TAGS{radiotap} },
   @{ $EXPORT_TAGS{requests} },

);

#sperimental tools

#sub Detect_Driver(){ # pure perl detect driver
#  use Sed;
#  my $comm = `ls -l /sys/class/net/wlo1/device/driver`;
#  if(! $comm) {
#    $comm = `ls -l /sys/class/net/wlan0/device/driver`;
#    }
 #  return(sed {s/^.*\/\([a-zA-Z0-9_-]*\)$/\1/} $comm); 
#}

sub RString_Gen(){ # adapted string for MAC address
  my @chars = ("a".."f", 0 .. 9);
  my $string;
  $string .= $chars[rand @chars] for 1..12;
  return($string);

}

sub RMAC_gen(){
  require Net::MAC;
  my $raw_mac = (Net::MAC->new('mac' => &RString_Gen(), 'die' => 0) );
  my $formatted_mac = $raw_mac->convert(
    'bit_group' => 8,  
    'delimiter' => ':'
);
  return ($formatted_mac);

}

sub Craft_TCP_Frame(){
  my ($src, $dst, $flags, $opts) = @_;
  use Net::Frame::Layer::TCP qw(:consts);
  my $TCP_packet = Net::Frame::Layer::TCP->new(
      src => $src,
      dst => $dst,
      ack => 0,
      off => 0,
      flags => $flags,
      options => $opts,
      win     => 0xffff
  );
  $TCP_packet->pack;
  return( $TCP_packet->dump );
}


sub Craft_RAW_Frame(){
   my ($raw, $payload, $nextlayer) = @_;
   use Net::Frame::Layer::RAW qw(:consts);
   my $RAW_packet = Net::Frame::Layer::RAW->new(
      raw => $raw,
      payload => $payload,
      nextLayer => $nextlayer
      );
   $RAW_packet->pack;
   return( $RAW_packet->dump );
}

sub Craft_NULL_Frame(){ # for 802.11
   use Net::Frame::Layer::NULL qw(:consts);
   my $NULL_packet = Net::Frame::Layer::NULL->new(
      type => NF_NULL_TYPE_80211,
   );
   $NULL_packet->pack;
   return( $NULL_packet->dump );
}

sub Craft_UDP_Frame(){
   my ($src, $dst, $length, $chksum) = @_;
   use Net::Frame::Layer::UDP;
   my $UDP_packet = Net::Frame::Layer::UDP->new(
      src => $src,
      dst => $dst,
      length => $length,
      checksum => $chksum
   );


}

__PACKAGE__->bootstrap($VERSION);


1;

__END__

