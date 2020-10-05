#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
# Main test for Air::Lorcon2's packet capabilities

use strict;
no strict 'subs';
use Data::Dumper qw(Dumper);
use Test;

BEGIN{ plan tests => 4 };

if ($<) {
    die "Error: test not executed as root\n";
}

use Air::Lorcon2 qw( :lorcon );
use Net::Pcap qw( pcap_lookupdev );

# set up Net::Pcap dev
my $pcap_err = '';
my $pcap_interface = pcap_lookupdev( \$pcap_err );

# set up Air::Lorcon2 dev

my $driver = "tuntap"; # test basic tuntap device

my $drv = lorcon_find_driver( $driver );

my $context = lorcon_create( $pcap_interface, $drv ) or die();

my $lcpa = lcpa_init(); # create lcpa type
my $Packet = lorcon_packet_from_lcpa( $context, $lcpa ); # crafted lorcon_packet_t type


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
