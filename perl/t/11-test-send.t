#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020

# test sending bytes

use Test;
use strict;
no strict 'subs';
use Air::Lorcon2 qw( :lorcon ); 
use Data::Dumper qw( Dumper );

BEGIN { plan tests => 1 };

use Net::Pcap qw(pcap_lookupdev);

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
if(! ( $context ) ){
	ok(0);
}

my $Packet = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"; # craft a null packet
my $LPacket = length( $Packet );
if( ! lorcon_send_bytes($context, $LPacket, $Packet) ){
	ok(0);
}else{
	ok(1);
}
ok(1);
