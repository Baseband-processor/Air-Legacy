# Made by Edoardo Mantovani, 2020

use Test;
use strict;
use Net::Pcap qw( pcap_lookupdev );
use Air::Lorcon2 qw(:lorcon); 

BEGIN { plan tests => 5 };


my $pcap_err = '';
my $pcap_intf = pcap_lookupdev( \$pcap_err );
# create $context in a safe way

my list
my $drv = lorcon_find_driver( $driver );
my $context = lorcon_create( $drv, $pcap_intf );
if(! ( $context ) ){
  return -1;
}

if( ( lorcon_open_inject( $context ) == -1 ) || ( lorcon_open_monitor( $context ) == -1 ) || ( lorcon_open_injmon( $context ) == -1 ){
  return -1;
 }
ok(1);
