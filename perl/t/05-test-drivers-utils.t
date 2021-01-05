# Made by Edoardo Mantovani, 2020
# test various drivers initialization functions and related capabilities

use strict;
no strict 'subs';
no warnings; # disable warnings for code integrity

use Test;
BEGIN{ plan tests => 1 };

use Air::Legacy qw( :lorcon );
use Net::Pcap qw( pcap_lookupdev );



# initialize Net::Pcap

my $pcap_error = '';
my $pcap_device = pcap_lookupdev( \$pcap_error );

# initialize Air::Lorcon2

## test tuntap device
my $driver = "tuntap";
my $drv = lorcon_find_driver( $driver );
my $context = lorcon_create( $pcap_device, $drv );

drv_tuntap_init( $context );


## TEST CAPABILITIES ##

tx80211_airjack_capabilities();

tx80211_airpcap_capabilities();

tx80211_hostap_capabilities();

tx80211_zd1211rw_capabilities();

tx80211_mac80211_capabilities();
  
tx80211_prism54_capabilities();

tx80211_rt61_capabilities();

tx80211_rt73_capabilities();

ok(1);
