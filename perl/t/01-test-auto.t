#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020

# Simple lorcon_auto_driver tester


use strict;
no strict 'ref';
use Net::Pcap qw( pcap_lookupdev );
use Test::More tests => 1;
BEGIN { use_ok("Air::Lorcon2") };
use Air::Lorcon2 qw(:lorcon); 

my $pcap_err = '';
my $pcap_intf = pcap_lookupdev( \$pcap_err );
lorcon_auto_driver( $pcap_intf );
ok 6;
