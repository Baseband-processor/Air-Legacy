#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020

sub BEGIN{

use strict;
use Net::Pcap qw( pcap_lookupdev pcap_open_live pcap_loop);
use Air::Legacy qw( :lorcon :packet_checksum  );

my $pcap_error = '';
my $pcap_interface = pcap_lookupdev( \$pcap_error );

# consider our driver the mac80211 layer
my $drv = lorcon_find_driver( "mac80211" );

my $lorcon_context = lorcon_create( $pcap_interface, $drv );

# open the pcap device for live listening
my $pcap = pcap_open_live( $pcap_interface, 1024, 1, 0, \$pcap_error );
 
# capture next 50 packets
pcap_loop($pcap, 50, \&process_packet, "");
 
# close the device
pcap_close($pcap);
 
sub process_packet {
    my ($user_data, $header, $packet) = @_;
    # convert pcap packet into lorcon2 packet
    my $packet_from_pcap = lorcon_packet_from_pcap( $lorcon_context, \$header, $packet );
    
    # calculate Shannon's entropy for each packet
    print packet_entropy( $packet_from_pcap ), "\n";

 }

 }
