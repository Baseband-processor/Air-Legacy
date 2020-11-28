#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020

sub BEGIN{

use strict;
use warnings;
use Air::Lorcon2 qw( :lorcon :reaver );

my $libWPS = libwps_meta();

# generate 2 random MAC address, just for try :)

my $mac1 = RMAC_gen();
my $SSid; #IDK
my $channel = int(rand(6));

# get the RSSI through Net::Wireless::802_11::WPA::CLI

my @BSSID;

my $x = 0;
sub get_rssi{
  require Net::Wireless::802_11::WPA::CLI;
  my $network = @_;
  local $wpa_cli = Net::Wireless::802_11::WPA::CLI->new();
  # scan the network
  $wpa_cli->scan();
  # parse the results
  foreach( $wpa_cli->scan_results() ){
    if( $_ =~ /:/ ){
      push @BSSID, $_;
    }else{
      if( $_->{ssid} =~ $network ){
        my $bssid = scalar( $BSSID[$x] );
        my %ss = $wpa->bss( $bssid );
        $ss{level} =~ /[0-9]/;
        if( length( abs( $a{level} ) ) >= 2 ){ # toggle the negative value from RSSI level
          return $a{level};
          print "\n";
        }
      }
    }
        
  }
my $network = <STDIN>;
chop( $network );
# this will find the network by its Essid and return the relative RSSI level
my $rssi = &get_rssi( $network );

wps_data_to_json($mac1, ssid, $channel,  $rssi, \"\x00\x00\x00\x00\x00\x00", $libWPS, \"10") 

sleep(5);
}
