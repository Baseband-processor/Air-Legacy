Air::Legacy
================================================

![image of wireless_security_protocols_bg](./wireless.jpg)

![coverage](https://progress-bar.dev/0?title=progress)  ![functions](https://progress-bar.dev/341?title=functions)  ![constants](https://progress-bar.dev/580?title=constants)  ![size](https://img.shields.io/github/languages/code-size/Baseband-processor/Air-Legacy) ![license](https://img.shields.io/github/license/Baseband-processor/Air-Legacy) ![Lcommits](https://img.shields.io/github/last-commit/Baseband-processor/Air-Legacy)  ![toplang](https://img.shields.io/github/languages/top/Baseband-processor/Air-Legacy) 
 ![release-date](https://img.shields.io/github/release-date/Baseband-processor/Air-Legacy)
 

**WHO I AM?**

Click [Here](https://github.com/Baseband-processor/Baseband-processor)

**PERL, WIRELESS SECURITY AND C**

Okay, the first project was Air::Lorcon2, an XS framework for using wireless penetration testing utilities into perl, the project growns exponentially, now there are more than 300 functions and reaver's utilities are appearing, in the future other famous wireless security tools will be added, aircrack-ng is the first of the list.

**Why not stop to Lorcon2?**

Lorcon2 is a great library, it offers a good abstraction which permits to interact with drivers and use them for sending packets or from sniff data, the only problem is that 
the possible attack scenarios with (the old) Air::Lorcon2 were reduced, this isn't good..
More attack can be used, more the efficency growns.

**REQUIREMENTS**

- [x] perl 
- [x] cpan and App::Cpan
- [x] libpcap
- [x] C compiler (gcc is fine)
- [ ] libnl-dev (optional, required only for using airpcap capabilities)
- [ ] libnet (required for using Airpwn capabilities)
- [x] linux-libc-dev (usefull for cfg80211 layer)

every requirements will be installed automatically by _install-deps.pl_ through OS packet manager.

**INSTALLATION**

for installing the *Air::Legacy* and *Lorcon2* libraries you just need to type:

```shell
   sudo make full

```

this will start the Makefile outside the C and perl directories, Lorcon2 Headers will be automatically installed in */usr/include* directory.

**TEST IF LORCON2 SUPPORTS LOCAL ADAPTERS**

for veryfing that everything works fine you can just start executing the following script:

```perl
#!/usr/bin/perl
# Made by Edoardo Mantovani, 2020

sub BEGIN{
 use Air::Legacy qw( :lorcon );
 print "avaiable drivers are:\n";
 print lorcon_actual_cards();
 sleep(2);
 print "\n while Lorcon2's supported drivers are:\n";
 print lorcon_supported_cards();

}
```

if this return no drivers or if in the output there isn't any wireless card try to init the interfaces though the *drv_* functions listed below:

- drv_madwifing_init
- drv_mac80211_init
- drv_file_init
- drv_rtfile_init
- drv_tuntap_init

for now only few network drivers are implemented (i.e mac80211 and madwifing), more on future.

Also tests are avaiable, but they won't cover the 300+ functions which Air::Legacy offers.

**DOCUMENTATION**

some resources about C Lorcon2 library and its related applications are here:
  - _HACKING EXPOSED™ WIRELESS: WIRELESS SECURITY SECRETS & SOLUTIONS SECOND AND THIRD EDITION_ 
  - [lorcon 2010 presentation at Stanford](https://slideplayer.com/slide/3519051/)
  - [lorcon 2007 presentation](https://www.willhackforsushi.com/presentations/shmoocon2007.pdf)
  - [official lorcon2 github repository](https://github.com/kismetwireless/lorcon) 
  - [getting-started-with-lorcon](http://blog.opensecurityresearch.com/2012/09/getting-started-with-lorcon.html)
  - [Beginner's Guide to Wireless Auditing ](https://community.broadcom.com/symantecenterprise/communities/community-home/librarydocuments/viewdocument?DocumentKey=ec8602a4-a4ec-4890-8771-9f24cd0bbb4b&CommunityKey=1ecf5f55-9545-44d6-b0f4-4e4a7f5f5e68&tab=librarydocuments)
  - [Schneier on Security - WiFi Driver Attack](https://www.schneier.com/blog/archives/2006/07/wifi_driver_att.html)
  - [Airpwn Documentation](http://airpwn.sourceforge.net/Documentation.html)
  - [Programming Wireless Security](https://www.sans.org/reading-room/whitepapers/wireless/programming-wireless-security-32813)
  

but, as *Mike Kershaw* said:

* _"there isn't really any documentation on the other functions, sorry; the code would be the best reference there. "_

so take advantage of the C open source code.


some resources about libnl library can be found here:
   - [libnl official site](https://www.infradead.org/~tgr/libnl/)
   - [Libmnl: minimalistic library for Netlink developers](https://workshop.netfilter.org/2010/wiki/images/0/0d/Libmnl.pdf)
   - [libnl official github repository](https://github.com/thom311/libnl)
   
 Resources about various aspect of wireless protocols:
   - [802.11 Authentication and Key Management](https://www.cwnp.com/uploads/802-11i_key_management.pdf)            
   - [Official Wi-fi standard specifications](https://www.wi-fi.org/discover-wi-fi/specifications)
   - [LDPA 802.11 guide, 2700+ pages](https://legal.vvv.enseirb-matmeca.fr/download/amichel/%5BStandard%20LDPC%5D%20802.11-2012.pdf)
   
 Resources about various wireless drivers:
   - [cfg80211 layer](https://www.kernel.org/doc/html/v4.12/driver-api/80211/cfg80211.html)
   - [mac80211 layer (first part)](https://www.kernel.org/doc/html/v4.12/driver-api/80211/mac80211.html)
   - [mac80211 layer (second part)](https://www.kernel.org/doc/html/v4.12/driver-api/80211/mac80211-advanced.html)
   
   
**PERL DOCUMENTATION**

if interested in more advanced examples for the perl library please go under the *examples/* directory.

some functions with the related explanation are presented here:


```perl
#!/usr/bin/perl

use strict;
use Net::Pcap qw( pcap_lookupdev );
use Air::Legacy qw( :lorcon ); # This will export every lorcon2's subroutines

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

```

**SPECIAL THANKS**

A great thanks to Andreas Hadjiprocopis (Contacts: [Perlmonks](https://www.perlmonks.org/?node_id=1165397), [email](mailto:bliako@cpan.org), [git](https://github.com/hadjiprocopis) ).

Probably the best collaborator I ever had, without him, the biggest part related to the C code won't work.

**other thanks**
* perlmonks community, especially *syphilis*  for his initial help.
* *Mike Kershaw* (aka Dragorn), the main developer of Lorcon2, who explained some obscure part of his code.
* *GomoR*, the old author, who never replied to my last emails, refused to help me even when I sent the 10.5 Air::Lorcon2 version.

**Future works and directions**

This library is the result of 3 months of hard work and, still now, there are several problem related to the perl-types conversion, 
Probably the project will grow even more, my future ideas are:

- [x] offer a full coverage for the Lorcon2 library
- [ ] develop a big amount of perl-based-subroutines, despite the function-avaiability, lorcon2 is a finite project, it's our work to make it infinite.
- [ ] Write a brief PDF manual centered on all Air::Legacy's functions
- [ ] add SPIKE interface for network protocol fuzzing
- [ ] add low level driver manipulation
- [ ] add customized complex formal methods analysis for wireless protocols
- [ ] add  WPA2 / WPA3 working authentication functions
- [ ] add Aircrack-ng working API
- [ ] fix memory leak bugs

**Other suggested Perl libraries for network security**

unfortunately perl doesn't have the same number of libraries as python, but some exists!
for starting I suggest to learn:

* [Socket](https://metacpan.org/pod/Socket)
* [Net::Pcap](https://metacpan.org/pod/Net::Pcap)
* [Net::Ncap](https://metacpan.org/pod/Net::Ncap)
* [Net::Frame](https://metacpan.org/pod/Net::Frame)
* [NetPacket](https://metacpan.org/pod/NetPacket)
* [Net::Write](https://metacpan.org/pod/Net::Write)
* [Net::Analysis](https://metacpan.org/pod/Net::Analysis)
* [Net::Silk](https://metacpan.org/pod/Net::Silk)
* [Net::Inspect](https://metacpan.org/pod/Net::Inspect)
* [Net::Tshark](https://metacpan.org/pod/Net::Tshark)
* [Net::Sharktools](https://metacpan.org/pod/Net::Sharktools)
* [File::PCAP](https://metacpan.org/pod/File::PCAP)
* [Net::P0f](https://metacpan.org/pod/Net::P0f)
* [Net::Pcap::Reassemble](https://metacpan.org/pod/Net::Pcap::Reassemble)
* [Nagios::NRPE](https://metacpan.org/pod/Nagios::NRPE)
* [Monitoring::Plugin](https://metacpan.org/pod/Monitoring::Plugin)
* [Net::Connection::Sniffer](https://metacpan.org/pod/Net::Connection::Sniffer)
* [Net::ARP](https://metacpan.org/pod/Net::ARP)
* [SNMPMonitor](https://metacpan.org/pod/SNMPMonitor)
* [Net::LibNIDS](https://metacpan.org/pod/Net::LibNIDS)
* [Parse::Snort](https://metacpan.org/pod/Parse::Snort)
* [Linux::TunTap](https://metacpan.org/pod/Linux::TunTap)
* [Net::Wireless::802_11::WPA::CLI](https://metacpan.org/pod/Net::Wireless::802_11::WPA::CLI)
* [IO::Socket::SSL::Intercept](https://metacpan.org/pod/IO::Socket::SSL::Intercept)

**PERL NETWORK SECURITY RESOURCE**

* _Automating System Administration with Perl_ (Probably one of the best books for the blue team field practices in Perl)
* _Network Programming With Perl (by Lincoln Stein, 2001)_ (even if old, still remains the best networking book for Perl developers)
* [Practical PERL for Security Practitioners](https://www.sans.org/reading-room/whitepapers/scripting/practical-perl-security-practitioners-1357)
* [Perl for Penetration Testing](https://www.slideshare.net/kost/perl-usage-in-security-and-penetration-testing)


**FREE DROPS**

Occasionally I'll drop some random hardware extension for Air::Legacy, this will include specific hardware, customized extension and new working modes.

**CURRENT VERSION**

After a long development stage, the actual version of Air::Legacy is the 00.00 for more about the enhancement of various functions see the _Change_ file inside the Perl directory.

**Air::Legacy's Metacpan version**

As you may understand, Air::Legacy has an autoinstaller, which couldn't be executed normally running the classical command:

```shell
sudo cpanm Air::Legacy
```
So in the future I'll fork the project for a cpan compatible library.

**Creating the challenge inside the community**

Air::Legacy is a powerfull perl library usefull for attacking wireless networks, unfortunately on CPAN there are no "antagonist" libraries for protecting wireless network,
yes, there is Net::Libnids, but is quite old and (probably) there won't be any significant updates.

The challenge is open for everyone who wants to develop a **N**etwork **I**ntrusion **D**etection **S**ystem in perl for counterattacking Air::Legacy attack vectors, 
every developer who wants to partecipate (and probably beat my library) is welcome!

**More informations**

If you are interested in new developments of Air::Legacy see its [official site](https://baseband-processor.github.io/WirelessLegacy.github.io/),
it is daily updated and shows last development for Air::Legacy.

Requests and collaborations
====================================
Feel free to email me at <Baseband@cpan.org>
- [x] I am open to suggestions, code improvement, collaboration and other requests



WARNINGS
======================

Many functions are still under heavy development cause the high number of buffers overflow,
for a detailed list of working functions, please refer to the list in the "working_functions" folder.

**COPYRIGHT AND LICENCE**

Copyright (c) 2020, *Edoardo Mantovani*
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

_THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE._

<img src="https://media3.giphy.com/media/ADiOs8AqeverrAuT4Q/giphy.gif" alt="drawing" width="2000"/>
