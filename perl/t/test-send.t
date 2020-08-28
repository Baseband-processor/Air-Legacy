# Made by Edoardo Mantovani, 2020

# test sending bytes

use Test;
use strict;
use Air::Lorcon2 qw( :lorcon ); 

BEGIN { plan tests => 5 };

my $driver;
my $list = lorcon_list_drivers();
foreach( @{ $list } ){
  if( %{ $_ } =~  "mac80211" ){
    $driver = "mac80211";
    break;
  }elsif( %{ $_ } =~  "madwifing"){
        $driver = "madwifing";
        break;
  }
    }

if( $driver ne "madwifing" || $driver ne "mac80211" ){
  return -1;
 }
  
my $drv = lorcon_find_driver( $driver );
my $context = lorcon_create( $drv, $pcap_intf );
if(! ( $context ) ){
  return -1;
}

my $Packet = "\x00\x00\x00\x00\x00\x00";
my $LPacket = length( $Packet );
lorcon_send_bytes($context, $LPacket, $Packet);

ok(1);
