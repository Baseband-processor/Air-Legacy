#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
# Basic utility for testing WEP decrypting capabilities

use strict;
no strict 'refs';

use Test::More skip_all => "uninplemented!\n";

use Air::Legacy qw( :lorcon );
use Net::Pcap qw( pcap_lookupdev );

my $pcap_err = '';
my $pcap_dev = pcap_lookupdev( \$pcap_err );

# use tuntap device as default
my $drv = lorcon_find_driver( "tuntap" );

# but if tuntap is KO..
if(undef( $drv ) ){
  foreach( lorcon_list_drivers() ){
    if( %{ $_ } =~ "mac80211" ){
      $drv = lorcon_find_driver( "mac80211" );
    }else{
     plan  skip_all "no drivers found!\n";
     
  }
    }
    
# create $context

my $bssd;
my $key;

my $context = lorcon_create( $pcap_dev, $drv );
lorcon_add_wepkey( $context, $bssd, $key, length($key) );
ok 6;
