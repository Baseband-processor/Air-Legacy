#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
# test pure-perl subroutines

use strict;
no strict 'subs';
use Test;

BEGIN{ plan tests => 1 };

use Air::Lorcon2 qw( :lorcon );

association_reason_codes_HASH();

dissociation_reason_codes_HASH();

channel_to_frequency_HASH();

RMAC_gen();

FindLinkage();

Detect_Driver();

Packet_to_hex("just a test");

Hex_to_packet("just a test");

ok(1);
