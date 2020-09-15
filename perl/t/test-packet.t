#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
# Main test for Air::Lorcon2's packet capabilities

use strict;
use warnings;
use Test;

BEGIN{ plain tests => 1 };

use Air::Lorcon2 qw( :lorcon );
use Net::Pcap qw( pcap_lookupdev );

# set up Net::Pcap dev
my $pcap_err = '';
my $pcap_interface = pcap_lookupdev( \$pcap_err );

# set up Air::Lorcon2 dev

my $driver;

my @list = lorcon_list_drivers();

foreach ( @list ){
        if ( Dumper( $_ ) =~ "mac80211"){
                $driver = "mac80211";
                break;
        }elsif ( Dumper( $_ ) =~ "madwifing" ){
                $driver = "madwifing";
                break;
        }elsif( Dumper( $_ ) =~ "file" ){
                $driver = "file";
                break;
        }
}


my $drv = lorcon_find_driver( $driver );

if(undef( $drv ) ){
  ok(0);
}else{
  ok(1);
}

my $context = lorcon_create( $pcap_interface, $drv );

if(undef( $context ) ){
  ok(0);
}else{
  ok(1);
}


my $lcpa = lcpa_init(); # create lcpa type
my $Packet = lorcon_packet_from_lcpa( $context, $lcpa ); # crafted lorcon_packet_t type

if( undef( $Packet ) ){
  ok(0);
}else{
  ok(1);
}

my $channel = rand(10); # set the maximun channel to 10
if( ! lorcon_packet_set_channel( $Packet, $channel ) ){ # try to set the channel for sending the packet
  ok(0);
}else{
  ok(1);
}

if(! lorcon_packet_decode( $Packet ) ) { # try to decode an empty packet
  ok(0);
}else{
  ok(1);
}

if( ! lorcon_packet_free( $Packet ) ) { # try to free an empty packet
  ok(0);
}else{
  ok(1);
}

ok(1);
