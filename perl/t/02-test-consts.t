#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
# test all exports

use Test;
BEGIN { plan tests => 1 };
use Air::Lorcon2 qw(:suites :ieee802_11 :network_const  :tx_80211  :wifi_mask :requests  :radiotap  :status :rate :extrapacket :channel :consts :lorcon ); # test all exports 
ok(1);
