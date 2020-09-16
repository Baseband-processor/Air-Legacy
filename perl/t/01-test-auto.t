# Made by Edoardo Mantovani, 2020

# Simple lorcon_auto_driver tester

use Test;
use strict;
use Net::Pcap qw( pcap_lookupdev );
BEGIN { plan tests => 1 };
use Air::Lorcon2 qw(:lorcon); 

my $pcap_err = '';
my $pcap_intf = pcap_lookupdev( \$pcap_err );
lorcon_auto_driver( $pcap_intf );
ok(1);
