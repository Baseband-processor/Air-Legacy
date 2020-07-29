package Net::Lorcon2;

use strict;
use warnings;

our $VERSION = '3.55';

use Class::Gomor::Array;
use base qw(Exporter DynaLoader Class::Gomor::Array);

use constant LORCON_EGENERIC => -1;
use constant LORCON_ENOTSUPP => -255;
use constant LORCON_STATUS_MAX => 1024;
use constant LORCON_MAX_PACKET_LEN => 8192;
use constant LORCON_CHANNEL_BASIC => 0;
use constant LORCON_CHANNEL_HT20 => 1;
use constant LORCON_CHANNEL_HT40P => 2;
use constant LORCON_CHANNEL_HT40M => 3;
use constant LORCON_CHANNEL_5MHZ =>  4;
use constant LORCON_CHANNEL_10MHZ => 5;
use constant LORCON_CHANNEL_VHT80 => 6;
use constant LORCON_CHANNEL_VHT160 => 7;
use constant LORCON_CHANNEL_VHT8080 => 8;  

use constant LORCON_RTAP_CHAN_TURBO => 0x0010;   
use constant LORCON_RTAP_CHAN_CCK  =>  0x0020;   
use constant LORCON_RTAP_CHAN_OFDM =>  0x0040; 
use constant LORCON_RTAP_CHAN_2GHZ =>  0x0080;
use constant LORCON_RTAP_CHAN_5GHZ =>  0x0100;
use constant LORCON_RTAP_CHAN_PASSIVE => 0x0200;
use constant LORCON_RTAP_CHAN_DYN => 0x0400;
use constant LORCON_RTAP_CHAN_GFSK => 0x0800;
use constant LORCON_RTAP_CHAN_STURBO => 0x2000;

use constant LORCON_RATE_DEFAULT => 0;
use constant LORCON_RATE_1MB => 2; 
use constant LORCON_RATE_2MB => 4; 
use constant LORCON_RATE_5_5MB => 11;
use constant LORCON_RATE_6MB => 12;
use constant LORCON_RATE_9MB => 18;
use constant LORCON_RATE_11MB => 22; 
use constant LORCON_RATE_12MB => 24; 
use constant LORCON_RATE_18MB => 36; 
use constant LORCON_RATE_24MB => 48; 
use constant LORCON_RATE_36MB => 72; 
use constant LORCON_RATE_48MB => 96; 
use constant LORCON_RATE_54MB => 108;
use constant LORCON_RATE_108MB => 216;

use constant LORCON_PACKET_EXTRA_NONE => 0;
use constant LORCON_PACKET_EXTRA_80211 => 1;
use constant LORCON_PACKET_EXTRA_8023 => 2;

use constant WLAN_STATUS_SUCCESS => 0;
use constant WLAN_STATUS_UNSPECIFIED_FAILURE => 1;
use constant WLAN_STATUS_CAPS_UNSUPPORTED => 10;
use constant WLAN_STATUS_REASSOC_NO_ASSOC => 11;
use constant WLAN_STATUS_ASSOC_DENIED_UNSPEC => 12;
use constant WLAN_STATUS_NOT_SUPPORTED_AUTH_ALG => 13;
use constant WLAN_STATUS_UNKNOWN_AUTH_TRANSACTION => 14;
use constant WLAN_STATUS_CHALLENGE_FAIL => 15;
use constant WLAN_STATUS_AUTH_TIMEOUT => 16;
use constant WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA => 17;
use constant WLAN_STATUS_ASSOC_DENIED_RATES => 18;
use constant WLAN_STATUS_ASSOC_DENIED_NOSHORT => 19;
use constant WLAN_STATUS_ASSOC_DENIED_NOPBCC => 20;
use constant WLAN_STATUS_ASSOC_DENIED_NOAGILITY => 21;
use constant WLAN_STATUS_INVALID_IE => 40;
use constant WLAN_STATUS_GROUP_CIPHER_NOT_VALID => 41;
use constant WLAN_STATUS_PAIRWISE_CIPHER_NOT_VALID => 42;
use constant WLAN_STATUS_AKMP_NOT_VALID => 43;
use constant WLAN_STATUS_UNSUPPORTED_RSN_IE_VERSION => 44;
use constant WLAN_STATUS_INVALID_RSN_IE_CAPAB => 45;
use constant WLAN_STATUS_CIPHER_REJECTED_PER_POLICY => 46;

use constant WLAN_FC_SUBTYPE_ASSOCREQ => 0;
use constant WLAN_FC_SUBTYPE_ASSOCRESP => 1;
use constant WLAN_FC_SUBTYPE_REASSOCREQ => 2;
use constant WLAN_FC_SUBTYPE_REASSOCRESP => 3;
use constant WLAN_FC_SUBTYPE_PROBEREQ => 4;
use constant WLAN_FC_SUBTYPE_PROBERESP => 5;
use constant WLAN_FC_SUBTYPE_BEACON => 8;
use constant WLAN_FC_SUBTYPE_ATIM =>  9;
use constant WLAN_FC_SUBTYPE_DISASSOC => 10;
use constant WLAN_FC_SUBTYPE_AUTH => 11;
use constant WLAN_FC_SUBTYPE_DEAUTH => 12;

# status and requests tags are from ie80211 file 

our %EXPORT_TAGS = (
   consts => [qw(
      LORCON_EGENERIC
      LORCON_ENOTSUPP
      LORCON_STATUS_MAX
      LORCON_MAX_PACKET_LEN
   )],
  radiotap => [qw(
      LORCON_RTAP_CHAN_TURBO
      LORCON_RTAP_CHAN_CCK
      LORCON_RTAP_CHAN_OFDM
      LORCON_RTAP_CHAN_2GHZ
      LORCON_RTAP_CHAN_5GHZ
      LORCON_RTAP_CHAN_PASSIVE
      LORCON_RTAP_CHAN_DYN
      LORCON_RTAP_CHAN_GFSK
      LORCON_RTAP_CHAN_STURBO
)],
  
  status => [qw(
      WLAN_STATUS_SUCCESS                     
      WLAN_STATUS_UNSPECIFIED_FAILURE         
      WLAN_STATUS_CAPS_UNSUPPORTED            
      WLAN_STATUS_REASSOC_NO_ASSOC            
      WLAN_STATUS_ASSOC_DENIED_UNSPEC         
      WLAN_STATUS_NOT_SUPPORTED_AUTH_ALG      
      WLAN_STATUS_UNKNOWN_AUTH_TRANSACTION    
      WLAN_STATUS_CHALLENGE_FAIL              
      WLAN_STATUS_AUTH_TIMEOUT                
      WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA 
      WLAN_STATUS_ASSOC_DENIED_RATES          
      WLAN_STATUS_ASSOC_DENIED_NOSHORT        
      WLAN_STATUS_ASSOC_DENIED_NOPBCC         
      WLAN_STATUS_ASSOC_DENIED_NOAGILITY      
      WLAN_STATUS_INVALID_IE                  
      WLAN_STATUS_GROUP_CIPHER_NOT_VALID      
      WLAN_STATUS_PAIRWISE_CIPHER_NOT_VALID   
      WLAN_STATUS_AKMP_NOT_VALID              
      WLAN_STATUS_UNSUPPORTED_RSN_IE_VERSION  
      WLAN_STATUS_INVALID_RSN_IE_CAPAB        
      WLAN_STATUS_CIPHER_REJECTED_PER_POLICY  
)],
  requests => [qw(
     WLAN_FC_SUBTYPE_ASSOCREQ    
     WLAN_FC_SUBTYPE_ASSOCRESP   
     WLAN_FC_SUBTYPE_REASSOCREQ  
     WLAN_FC_SUBTYPE_REASSOCRESP 
     WLAN_FC_SUBTYPE_PROBEREQ    
     WLAN_FC_SUBTYPE_PROBERESP   
     WLAN_FC_SUBTYPE_BEACON      
     WLAN_FC_SUBTYPE_ATIM        
     WLAN_FC_SUBTYPE_DISASSOC    
     WLAN_FC_SUBTYPE_AUTH        
     WLAN_FC_SUBTYPE_DEAUTH      

)],

  rate => [qw(
      LORCON_RATE_DEFAULT     
      LORCON_RATE_1MB               
      LORCON_RATE_2MB               
      LORCON_RATE_5_5MB            
      LORCON_RATE_6MB              
      LORCON_RATE_9MB              
      LORCON_RATE_11MB              
      LORCON_RATE_12MB              
      LORCON_RATE_18MB              
      LORCON_RATE_24MB              
      LORCON_RATE_36MB              
      LORCON_RATE_48MB              
      LORCON_RATE_54MB             
      LORCON_RATE_108MB       

)],

  extrapacket => [qw(
  LORCON_PACKET_EXTRA_NONE
  LORCON_PACKET_EXTRA_80211         
  LORCON_PACKET_EXTRA_8023        
)],

  channel => [qw(
      LORCON_CHANNEL_BASIC
      LORCON_CHANNEL_HT20
      LORCON_CHANNEL_HT40P
      LORCON_CHANNEL_HT40M
      LORCON_CHANNEL_5MHZ
      LORCON_CHANNEL_10MHZ
      LORCON_CHANNEL_VHT80
      LORCON_CHANNEL_VHT160
      LORCON_CHANNEL_VHT8080

)],

   subs => [qw(
      lorcon_list_drivers
      lorcon_find_driver
      lorcon_set_datalink
      lorcon_get_datalink
      lorcon_create
      lorcon_free_driver_list
      lorcon_free
      lorcon_set_timeout
      lorcon_get_timeout
      lorcon_open_monitor
      lorcon_open_injmon
      lorcon_set_vap
      lorcon_get_vap
      lorcon_get_capiface
      lorcon_auto_driver
      lorcon_get_driver_name
      lorcon_get_error
      lorcon_open_inject
      lorcon_send_bytes
      lorcon_get_useraux
      lorcon_set_useraux
      lorcon_packet_free
      lorcon_packet_decode
      lorcon_packet_set_channel
      lorcon_packet_get_channel
      lorcon_loop 
      lorcon_packet_to_dot3
      lorcon_set_hwmac
      lorcon_get_hwmac
      lorcon_multi_remove_interface_error_handler
      lorcon_multi_interface_get_lorcon
      lorcon_multi_get_next_interface
      lorcon_multi_get_interfaces
      lorcon_multi_del_interface
      lorcon_multi_add_interface
      lorcon_multi_free
      lorcon_multi_create
      lorcon_get_complex_channel 
      lorcon_set_complex_channel
      lorcon_ifdown
      locon_packet_get_bssid_mac
      lorcon_packet_get_dest_mac
      lcpf_randmac
      lorcon_packet_get_source_mac
      lorcon_ifup
      lorcon_packet_from_dot3
      lorcon_packet_to_dot3
      lorcon_breakloop
      lorcon_set_filter
      lorcon_next_ex
      lorcon_get_selectable_fd
      lorcon_packet_set_freedata
      lorcon_get_pcap
      drv_madwifing_init
      drv_madwifing_listdriver
      lorcon_close
      lorcon_inject
      lorcon_add_wepkey
       
   )],
);

our @EXPORT = (
   @{$EXPORT_TAGS{consts}},
   @{$EXPORT_TAGS{subs}},
   @{ $EXPORT_TAGS{channel} },
   @{ $EXPORT_TAGS{extrapacket} },
   @{ $EXPORT_TAGS{rate} },
   @{ $EXPORT_TAGS{status} },
   @{ $EXPORT_TAGS{radiotap} },

);

__PACKAGE__->bootstrap($VERSION);

our @AS = qw(
   driver
   interface
   _drv
   _context
);

__PACKAGE__->cgBuildAccessorsScalar(\@AS);
__PACKAGE__->cgBuildIndices;

sub new {
   my $self = shift->SUPER::new(
      driver    => $_[2],
      interface => $_[1],
      @_,
   );
   my $drv = lorcon_find_driver($self->driver);
   if (! $drv) {
      die  "[*] new: lorcon_find_driver: failed\n";
      return;
   }
   $self->_drv( $drv ) ;
   my $context = lorcon_create($self->interface, $self->_drv); #_drv
   if (! $context) {
      die "[*] new: lorcon_create: failed\n";
      return;
   }
   $self->_context($context) or die $!;
   return $self;
}

sub setInjectMode {
   my $self = shift;
   my $r = lorcon_open_inject($self->_context);#->_context);
   if ($r == -1) {
      die "[*] setInjectMode: lorcon_open_inject: " . lorcon_get_error( $self->_context ) . "\n";
      return;
   }
   return 1;
}

sub sendBytes {
   my $self = shift;
   my ($bytes) = @_;
   my $r = lorcon_send_bytes($self->_context, length( $bytes ), $bytes );
   if ($r < 0) {
      die "[*] sendBytes: lorcon_send_bytes: " . lorcon_get_error( $self->_context ) . "\n";
      return;
   }
   return $r;
}

sub DESTROY {
   my $self = shift;
   if (!(defined($self->_context))) {
      lorcon_close($self->_context);
      lorcon_free($self->_context);
      die "[*] DEBUG: lorcon_DESTROY\n";

   }
}

1;

__END__

=head1 NAME

Net::Lorcon2 - Raw wireless packet injection using the Lorcon2 library

=head1 SYNOPSIS

  use Net::Lorcon2 qw(:subs);

  my $if     = "wlan0";
  my $driver = "mac80211";
  my $packet = "G"x100;

  #
  # Usage in an OO-way
  #

  my $lorcon = Net::Lorcon2->new(
     interface => $if,
     driver    => $driver,
  );

  $lorcon->setInjectMode;

  my $t = $lorcon->sendBytes($packet);
  if (! $t) {
     print "[-] Unable to send bytes\n";
     exit 1;
  }

  #
  # Usage with lorcon2 library API
  #

  my $drv = lorcon_find_driver($driver);
  if (! $drv) {
     print STDERR "[-] Unable to find DRV for [$driver]\n";
     exit 1;
  }

  my $lorcon = lorcon_create($if, $drv);
  if (! $lorcon) {
    print STDERR "[-] lorcon_create failed\n";
    exit 1;
  }

  my $r = lorcon_open_inject($lorcon);
  if ($r == -1) {
    print STDERR "[-] lorcon_open_inject: ".lorcon_get_error($lorcon)."\n";
    exit 1;
  }

  my $t = lorcon_send_bytes($lorcon, length($packet), $packet);
  print "T: $t\n";

=head1 DESCRIPTION

This module enables raw 802.11 packet injection provided you have a Wi-Fi card
supported by Lorcon2.

Lorcon2 can be obtained from L<http://802.11ninja.net/svn/lorcon/>.

This version has been tested against the following revision:

L<http://802.11ninja.net/svn/lorcon/tags/lorcon2-200911-rc1>

=head1 FUNCTIONS

=over 4

=item B<lorcon_add_wepkey>

=item B<lorcon_auto_driver>

=item B<lorcon_close>

=item B<lorcon_create>

=item B<lorcon_find_driver>

=item B<lorcon_free>

=item B<lorcon_free_driver_list>

=item B<lorcon_get_capiface>

=item B<lorcon_get_channel>

=item B<lorcon_get_driver_name>

=item B<lorcon_get_error>

=item B<lorcon_get_selectable_fd>

=item B<lorcon_get_timeout>

=item B<lorcon_get_vap>

=item B<lorcon_get_version>

=item B<lorcon_inject>

=item B<lorcon_list_drivers>

=item B<lorcon_open_inject>

=item B<lorcon_open_injmon>

=item B<lorcon_open_monitor>

=item B<lorcon_send_bytes>

=item B<lorcon_set_channel>

=item B<lorcon_set_filter>

=item B<lorcon_set_timeout>

=item B<lorcon_set_vap>

=back

=head1 METHODS

=over 4

=item B<new>(device, driver) 

Constructs a new C<Net::Lorcon2> object. C<device> is the name of the device to
use for packet injection. C<driver> is the driver to use (one of the names
returned from getcardlist)

=item B<setInjectMode> ()

Sets the inject mode for the card.

=item B<sendBytes> (data)

Send raw data in the air.

=back

=head1 CONSTANTS

Load them: use Net::Lorcon2 qw(:consts);

=over 4

=item B<LORCON_EGENERIC>

=item B<LORCON_ENOTSUPP>

=back

=head1 SEE ALSO

L<lorcon2(7)>, 802.11 Wireless Networks by Matthew Gast.

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret, E<lt>gomor at cpan dot orgE<gt> (current maintainer and developper of Net::Lorcon2)

David Leadbeater, E<lt>dgl at dgl dot cxE<gt> (original author)

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2010-2015 by Patrice E<lt>GomoRE<gt> Auffret

Copyright (C) 2007-2008 by David Leadbeater and Patrice E<lt>GomoRE<gt> Auffret

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut
