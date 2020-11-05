#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
# test packet checksum capabilities of Air::Legacy

use strict;
use warnings;
use Test;

BEGIN{ plan tests => 1 };

use Air::Legacy qw( :packet_checksum );

my $packet = "\x00\x00\x00\x00\x00\x00"; # NULL packet

packet_crc( $packet );
packet_entropy( $packet );

ok 1;
