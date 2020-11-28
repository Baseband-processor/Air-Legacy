#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020 
# Craft and send WPS packets

sub BEGIN{

use strict;
use warnings;
use Term::ANSIColor;
use Air::Lorcon2 qw( :lorcon :reaver );

# NOTE: lorcon export is usefull only for pcap_inject function

use Net::Wireless::802_11::WPA::CLI; 

# NOTE: Net::Wireless::802_11::WPA::CLI is usefull for retrieve bssid and Essid informations about APs

my $scan = Net::Wireless::802_11::WPA::CLI->new();

my $essid = <STDIN>;
chomp( $essid );

sub Wireless_Scan(){
  $scan->scan();
  foreach ( $scan->scan_results() ){
    if($_ =~ /:/){
      push @BSSID, $_;
    }else{
       if(length($_->{ssid}) != 25){
         while(length($_->{ssid}) != 25){    # leverage the distance between the SSID and the '|' 
            chop($_->{ssid}) if (length($_->{ssid}) > 25);
            $_->{ssid} .= " " if (length($_->{ssid}) < 25);
            }
          } 
     print  colored(['red'], $_->{ssid}, '   |  ', colored(['cyan'],$BSSID[$x]), ' ', colored(['green'], $_->{frequency}), ' ', colored(['yellow'], $_->{flags}), "\n"); # print various informations in a fashion/colored way
     $x++; 
}  
  
  }

}
 

}
&Wireless_Scan();

sleep(2);
my $bssid = <STDIN>;
chomp( $bssid );
my $probe = build_wps_probe_request( \$bssid, \$essid);


# Craft a Lorcon2 pcap object compatible type

my $driver = <STDIN>;
chomp( $driver ); # Delete the 'ret' character from the $driver string
my $drv = lorcon_find_driver( $driver );

my $context = lorcon_create("wlan0", $drv) or die $!; # automatically use wlan0 interface

my $pcap = lorcon_get_pcap( $context );

# send WPS probe packet

pcap_inject( $pcap, $probe, length( $probe ) );
}
