# Made by Edoardo Mantovani, 2020
# test packet checksum capabilities of Air::Legacy

use strict;
use warnings;
use Test;

BEGIN{ plan tests => 1 };

# export also lorcon functions for crafting an AirLorcon packet type
use Air::Legacy qw( :packet_checksum :lorcon );

my $packet = "\x00\x00\x00\x00\x00\x00"; # NULL packet

my $lcpa = lcpa_init();
my $AirLorconPacket = lorcon_packet_from_lcpa( $lcpa );
packet_crc( $packet );
packet_entropy( $AirLorconPacket );

ok 1;
