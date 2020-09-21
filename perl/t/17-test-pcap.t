#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
# test lorcon_get_pcap and other related pcap utilities

use strict;
no strict 'refs';
no strict 'subs';

use Test;

BEGIN{ plan tests => 1 };

use Air::Lorcon2 qw( :lorcon );
use Data::Dumper qw( Dumper );
use Net::Pcap qw( pcap_lookupdev );

my $pcap_err = '';
my $pcap_intf = pcap_lookupdev( \$pcap_err );
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
my $context = lorcon_create( $pcap_intf, $drv );

my $lorcon_to_pcap = lorcon_get_pcap( $context ); # drop the pcap object

# Set various pcap functions

pcap_can_set_rfmon( $lorcon_to_pcap ) or die $!;

my $Packet = "\x00\x00\x00\x12";

pcap_sendpacket( $lorcon_to_pcap,  $Packet, length( $Packet ) );


ok(1);
