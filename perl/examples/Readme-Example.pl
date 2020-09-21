use strict;
use Net::Pcap qw( pcap_lookupdev );
use Data::Dumper qw(Dumper);
use Air::Lorcon2 qw(:lorcon); # This will export every lorcon2's subroutines

my $pcap_err = '';
my $pcap_interface = pcap_lookupdev( \$pcap_err ); # This will give us the best interface avaiable for sniffing 

print Dumper( lorcon_list_drivers() ) or die $!;

# NOTE: lorcon_list_drivers will show supported drivers avaiable in the current host, while tx80211_getcardlist function
# will show the lorcon's supported network cards list

my $driver = <STDIN>;
chomp( $driver ); # Delete the 'ret' character from the $driver string
my $drv = lorcon_find_driver( $driver );

my $context = lorcon_create($pcap_interface, $drv) or die $!;

# From here we have access to an huge number of functions, some simple examples are:

lorcon_ifdown( $context ) or die lorcon_get_error( $context ); # Set interface 'down'
lorcon_ifup( $context ) or die lorcon_get_error( $context ); # Set interface 'up'

my $channel = 2;

lorcon_set_channel( $context, $channel ) or die lorcon_get_error( $context ); # set channel to 2
lorcon_get_channel( $context ) or die lorcon_get_error( $context ); # return the channel, in this case 2

lorcon_open_inject (  $context ) or die lorcon_get_error( $context ); # set the injection mode
lorcon_open_monitor(  $context ) or die lorcon_get_error( $context ); # set the monitor mode
lorcon_open_injmon (  $context ) or die lorcon_get_error( $context ); # set both

# We can also initialize our preferred network driver using

drv_madwifing_init( $context ); 

# ||

drv_mac80211_init( $context ); 

# And if we add a packet the possible uses  grows exponentially:

my $Packet = "\xdd\x09\x00\x50\xf2\x04\x10\x4a\x00\x01\x10"; # WPS probe packet taken by Air::Reaver, another my module for Reaver

# || 

my $Packet = Packet_to_hex("sample_packet"); # return a hexadecimal version of "sample_packet" with \x format

lorcon_send_bytes( $context, length($Packet), \$Packet ); # this will send the raw bytes though the network

$Packet = undef;

# NOTE:
# Since version 17.6 is possible to use also this simplified function:

print Send_Bytes( $context, $Packet); 
# The $Packet length is processed in the Back-End.


my $lcpa = lcpa_init();
$Packet = packet_from_lcpa( $context, $lcpa ); # return a AirLorconPacket variable

# decode the packet
lorcon_packet_decode( $Packet );

# Get a valid Pcap object, usefull for built-in (or with Net::Pcap) routines

my $pcap = lorcon_get_pcap( $context );

# Set frequency using libpcap

pcap_can_set_rfmon( $pcap );

# Send packet using libpcap

pcap_sendpacket( $pcap, $Packet, length( $Packet ) );

# Note: pcap_sendpacket and pcap_inject are almost the same function, the only difference stands in the output: for pcap_inject it will be the packet's number of bytes

# For more info see: https://linux.die.net/man/3/pcap_inject

# Lorcon2 offers also the possibility of sending bytes using specific drivers, some example are as follow:

madwifing_sendpacket( $context, $Packet );
mac80211_sendpacket( $context, $Packet );

# Note that $Packet has _lorcon_packet_t_ type

my $raw_bytes = "\x00\x00\x00\x00\x00";
tuntap_sendbytes( $context, length( $raw_bytes ), \$raw_bytes );
