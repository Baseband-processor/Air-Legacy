#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020

#	Perl version of beacon_flood_lcpa.c (original author: brad.antoniewicz@foundstone.com)
#	simple IEEE 802.11 beacon flooder using Air::lorcon2 
#	packet assembly functionality

use strict;
use warnings;
use Air::Legacy qw( :lorcon );

my $SSID = shift or die "./beacon_flood_lcpa.pl <SSID> <interface> <driver> <channel>\n";
my $interface = shift or die "./beacon_flood_lcpa.pl <SSID> <interface> <driver> <channel>\n";
my $driver = shift or die "./beacon_flood_lcpa.pl <SSID> <interface> <driver> <channel>\n";
my $channel = shift or die "./beacon_flood_lcpa.pl <SSID> <interface> <driver> <channel>\n";

my $mac  = "\x00\xDE\xAD\xBE\xEF\x00";

my $rates = "\x8c\x12\x98\x24\xb0\x48\x60\x6c"; 

my $Interval = 100;

my $capabilities = 0x0421;

# create lorcon context

my $drv = lorcon_find_driver( $driver ) or die $!; 
my $context = lorcon_create( $interface, $driver ) or die $!;

lorcon_open_injmon( $context ) or die lorcon_get_error( $context );
print "Current VAP is: " . lorcon_get_vap( $context ); # return the name of the Virtual Access Point

# set the channel

lorcon_set_channel( $context, $channel ) or die Air::Lorcon2::lorcon_get_error( $context );

# flooding part

while(1){
	my $timestamp = time * 1000; # implement better
	my $meta = lcpa_init(); # create lcpa instance
	lcpf_beacon( $meta, $mac, $mac, "0x00", "0x00", "0x00", "0x00", $timestamp, $Interval, $capabilities);
	lcpf_add_ie( $meta, 0, length( $SSID ), $SSID ); 
	lcpf_add_ie( $meta, 1, ( length( $rates ) -1 ), \$rates);
	lcpf_add_ie( $meta, 3, 1, \$channel);
# Append IE Tags 42/47 for ERP Info 
	lcpf_add_ie( $meta, 42, 1, "\x05");
	lcpf_add_ie( $meta, 47, 1, "\x05");
# Convert Lorcon metapack to lorcon packet	
	my $packet = lorcon_packet_from_lcpa( $context, $meta );
	lorcon_inject( $context, $packet ) or die lorcon_get_error( $context );
	print "Hit CTRL + C to stop...\r";
	
	lcpa_free( $meta );
}


lorcon_close( $context );
lorcon_free( $context );
