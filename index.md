
Air::Legacy is growing, now it is ready to infect also the WWW!


<img src="https://static.wixstatic.com/media/d41190_4c5ebba9c3604c4a8947e3945dcd4d55~mv2.gif" alt="drawing" width="2000"/>

*Every minute ~2000 people are affected by cyber attacks, most of those are phishing attacks*

Synopsis
====================================================


This is the most basic example avaiable of Air::Legacy, it uses only a small sets of subroutines taken from the original Lorcon2 API     


Now, Lorcon2 has a limited attack set, you can create network fuzzers and sniff packets from multiple interfaces,but it isn't able  to send WPS packet or to bruteforce WPA/WPA2 packets, this would be a serious limitation, obviously.

Air::Legacy is the union of every wireless attacks implementation into a single, compact perl library.

```perl
#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020

sub BEGIN{

use strict;
use Net::Pcap qw( pcap_lookupdev );
use Air::Legacy qw(:lorcon); # This will export every lorcon2's subroutines

my $pcap_err = '';
my $pcap_interface = pcap_lookupdev( \$pcap_err ); # This will give us the best interface avaiable for sniffing 

print lorcon_actual_cards() or die $!;

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

my $Packet = "\xdd\x09\x00\x50\xf2\x04\x10\x4a\x00\x01\x10"; # WPS probe packet

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

# Note that $Packet has lorcon_packet_t type

my $raw_bytes = "\x00\x00\x00\x00\x00";
tuntap_sendbytes( $context, length( $raw_bytes ), \$raw_bytes );

}
```


**Send WPS probe packet**

```perl
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


```

**Convert Pcap packet to Lorcon2 packet and analyze them**


```perl
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
```

**Represent WPS data into JSON file**

```perl
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
my $rssi; # STILL WIP

wps_data_to_json($mac1, ssid, $channel,  rssi, \"\x00\x00\x00\x00\x00\x00", $libWPS, \"10") 

sleep(5);
}
```

Some Attack Ideas
==================================================================

* Create a passive WPA enterprise packet analyzer which studies some common patterns inside packets and try to craft a  fake one.
* Create an advanced traffic analysis framework which works out of Wlans using entropy


Companion Libraries
==================================================================

As you have seen, usually Air::Legacy uses some companion libraries for extending its attack horizont, probably the most important library here is Net::Pcap, which is based on the famous libpcap library, also Air::Legacy support some additional pcap functions (see pcap_inject).


Requests and collaborations
==============================
Feel free to email me at Baseband@cpan.org

I am open to suggestions, code improvement, collaboration and other requests
 
<img src="https://media3.giphy.com/media/ADiOs8AqeverrAuT4Q/giphy.gif" alt="drawing" width="2000"/>
