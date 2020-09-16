#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020

# main test routine for Air::Lorcon2

use Test;
use strict;
no strict 'subs';


BEGIN { plan tests => 1 };

use Air::Lorcon2 qw( :lorcon ); 
use Net::Pcap qw( pcap_lookupdev );
use Data::Dumper qw(Dumper);

my $pcap_err = '';
my $pcap_intf = pcap_lookupdev( \$pcap_err );
# create $context in a safe way

# automatically search for drivers
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

if( lorcon_open_inject( $context ) == -1 ) {
	ok(0);
}

if( lorcon_open_monitor( $context ) == -1 ) {
	ok(0);
}

if( lorcon_open_injmon( $context ) == -1  ) {
  ok(0);
 }

ok(1);
