#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
# test lcpf functions, necessary for packet creation capabilities

use strict;
no strict 'subs';
no strict 'refs';

use warnings;

use Test::More tests => 1;

BEGIN{ use_ok('Air::Lorcon2') };

# craft lcpa_meta object
my $lcpa = lcpa_init();

# generate random MACs address

sub mac_gen(){
  my $rand_mac = RMAC_gen();
  return ( $rand_mac );
}

lcpf_80211headers($lcpa, "1", "2", "3", "4", &mac_gen(), &mac_gen(), &mac_gen(), &mac_gen(), 0, 1);

lcpf_qos_data($lcpa, "1", "1", &mac_gen(), &mac_gen(), &mac_gen(), &mac_gen(), 1, 0);

lcpf_beacon($lcpa, &mac_gen(), &mac_gen(), 1, 1, 1, 1, "0x00", 1, 1);


lcpf_deauth
lcpf_disassoc
lcpf_probereq
lcpf_proberesp
lcpf_rts
lcpf_80211ctrlheaders
lcpf_authreq
lcpf_authresq
lcpf_assocreq

ok 6;
