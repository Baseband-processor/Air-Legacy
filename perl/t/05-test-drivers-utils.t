#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
# test various drivers initialization functions and related capabilities

use strict;
no strict 'subs';
no warnings; # disable warnings for code integrity

use Test;
BEGIN{ plan tests => 1 };

use Air::Lorcon2 qw( :lorcon );
use Net::Pcap qw( pcap_lookupdev );
use Data::Dumper qw(Dumper);


# initialize Net::Pcap

my $pcap_error = '';
my $pcap_device = pcap_lookupdev( \$pcap_error );

# initialize Air::Lorcon2

my $driver = "madwifing";
my $drv = lorcon_find_driver( $driver ); 
my $context = lorcon_create( $pcap_device, $drv );

## test madwifing device

if( ! madwifing_openmon_cb( $context ) ){
  ok(0);
}else{
  ok(1);
}

if( ! drv_madwifing_init( $context ) ){
  ok(0);
}else{
  ok(1);
}

## test tuntap device

$context = undef;
$drv = undef;

$driver = "tuntap";
$drv = lorcon_find_driver( $driver );
$context = lorcon_create( $pcap_device, $drv );

if( ! drv_tuntap_init( $context ) ){
  ok(0);
}else{
  ok(1);
}

## test file device

$context = undef;
$drv = undef;

$driver = "file";
$drv = lorcon_find_driver( $driver );
$context = lorcon_create( $pcap_device, $drv );

if( ! drv_file_init( $context ) ){
  ok(0);
}else{
  ok(1);
}

## test rtfile device

$context = undef;
$drv = undef;

$driver = "rtfile";
$drv = lorcon_find_driver( $driver );
$context = lorcon_create( $pcap_device, $drv );

if( ! drv_rtfile_init( $context ) ){
  ok(0);
}else{
  ok(1);
}

## test mac80211 device

$context = undef;
$drv = undef;

if( %{ lorcon_list_drivers() } =~ "mac80211" ){
        $driver = "mac80211";
        $drv = lorcon_find_driver( $driver );
        $context = lorcon_create( $pcap_device, $drv );

        if( ! drv_mac80211_init( $context ) ){
                  ok(0);
        }else{
                 ok(1);
        }

}

## TEST CAPABILITIES ##

if( ! tx80211_airjack_capabilities() ){
    ok(0);
}else{
  ok(1);
}

if( ! tx80211_airpcap_capabilities() ){
  ok(0);
}else{
  ok(1);
}

if( ! tx80211_hostap_capabilities() ){
  ok(0);
}else{
  ok(1);
}

if( ! tx80211_zd1211rw_capabilities() ){
  ok(0);
}else{
  ok(1);
}

if( ! tx80211_mac80211_capabilities() ){
  ok(0);
}else{
  ok(1);
}

if( ! tx80211_prism54_capabilities() ){
  ok(0);
}else{
  ok(1);
}

if( ! tx80211_rt61_capabilities() ){
  ok(0);
}else{
  ok(1);
}

ok(1);
