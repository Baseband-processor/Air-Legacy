#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
# test ajinj functions

use strict;
use warnings;
use Test;

use Test::More skip_all => "still under WIP!";
 
BEGIN{plan tests => 1};

use Air::Legacy qw( :lorcon );

# craft tx80211 type
my $tx80211 = tx80211_meta();

ajinj_open( $tx80211 );

aj_setnonblock( $tx80211, 1);

ajinj_close( $tx80211 );

ok(1);
