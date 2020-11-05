#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
# simple test program for inspection utilities

use strict;
no strict 'subs';
use Test;

BEGIN{ plan tests => 6 };

use Air::Legacy qw( :lorcon );
use Net::Pcap qw( pcap_lookupdev );

my $lcpa = lcpa_init();

# Net::Pcap runtimes

my $pcap_err = '';
my $pcap_device = pcap_lookupdev( \$pcap_err );


my $drv = lorcon_find_driver( "tuntap" );

my $context = lorcon_create( $pcap_device, $drv );

# craft an empty packet

my $Packet = lorcon_packet_from_lcpa( $context, $lcpa );

lorcon_packet_get_dot11_extra($Packet );

if( ! lorcon_packet_get_dot3_extra( $Packet ) ) {
  ok(0);
}else{
  ok(1);
}

if( ! lorcon_packet_get_source_mac( $Packet ) ) {
  ok(0);
}else{
  ok(1);
}

if( ! lorcon_packet_get_dest_mac( $Packet ) ) {
  ok(0);
}else{
  ok(1);
}


if( ! lorcon_packet_get_llc_type( $Packet ) ) {
  ok(0);
}else{
  ok(1);
}

if( ! lorcon_packet_get_interface( $Packet ) ) {
  ok(0);
}else{
  ok(1);
}
