#!perl

use strict;
use warnings;

use Net::Pcap qw( pcap_lookupdev );
use Data::Dumper qw(Dumper);
use Air::Lorcon2 qw(:lorcon); # This will export every lorcon2 subroutines

my $pcap_err = '';
my $pcap_interface = pcap_lookupdev( \$pcap_err ); # This will give us the best interface avaiable for sniffing 

print Dumper( Air::Lorcon2::lorcon_list_drivers() ) or die $!;
my $driver = <STDIN>;
chomp( $driver ); # Delete the 'ret' character from the $driver string
my $drv = Air::Lorcon2::lorcon_find_driver( $driver );

my $context = Air::Lorcon2::lorcon_create($pcap_interface, $drv) or die $!;

# From here we have access to an huge number of functions, some simple examples are:

Air::Lorcon2::lorcon_ifdown( $context ) or die Air::Lorcon2::lorcon_get_error( $context ); # Set interface 'down'
Air::Lorcon2::lorcon_ifup( $context ) or die Air::Lorcon2::lorcon_get_error( $context ); # Set interface 'up'

my $channel = 2;

Air::Lorcon2::lorcon_set_channel( $context, $channel ) or die Air::Lorcon2::lorcon_get_error( $context ); # set channel to 2
Air::Lorcon2::lorcon_get_channel( $context ) or die Air::Lorcon2::lorcon_get_error( $context ); # return the channel, in this case 2

Air::Lorcon2::lorcon_open_inject (  $context ) or die Air::Lorcon2::lorcon_get_error( $context ); # set the injection mode
Air::Lorcon2::lorcon_open_monitor(  $context ) or die Air::Lorcon2::lorcon_get_error( $context ); # set the monitor mode
Air::Lorcon2::lorcon_open_injmon (  $context ) or die Air::Lorcon2::lorcon_get_error( $context ); # set both

# We can also initialize our preferred network driver using

Air::Lorcon2::drv_madwifing_init( $context ); 

# ||

Air::Lorcon2::drv_mac80211_init( $context ); 

# And if we add a packet the possible uses  grows exponentially:

my $Packet = "\xdd\x09\x00\x50\xf2\x04\x10\x4a\x00\x01\x10"; # WPS probe packet taken by Air::Reaver, another my module for Reaver

Air::Lorcon2::lorcon_send_bytes( $context, length($Packet), \$Packet ); # this will send the raw bytes though the network

# NOTE:
# Since version 17.6 is possible to use also this simplified function:

print Air::Lorcon2::Send_Bytes( $context, $Packet); 
# The $Packet length is processed in the Back-End.
