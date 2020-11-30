#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
# test all exports

use strict;
no strict 'refs';
use Test::More tests => 2;
BEGIN { use_ok( 'Air::Legacy' ); };
use Air::Legacy qw(:suites :ieee802_11 :osdep :ioctls :wps_constants  :reaver :packet_checksum :network_const  :iw :wifi_commands  :tx_80211  :rx_frames :wifi_mask :requests  :radiotap  :status :rate :extrapacket :channel :consts :lorcon ); # test all exports 
ok 1;
