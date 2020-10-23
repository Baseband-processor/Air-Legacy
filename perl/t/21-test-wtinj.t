#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
# test wtinj functions

use strict;
use warnings;

use Test;

BEGIN{ plan tests => 1};

use Air::Lorcon2 qw( :lorcon );

# craft tx80211 object
my $tx80211 = tx80211_meta();


wtinj_open( $tx80211 );
wtinj_close( $tx80211 );

# set channel 3
wtinj_setchannel( $tx80211, 3);

# return the channel

if( wtinj_getchannel( $tx80211 ) != 3 ){
  ok(0);
}

wtinj_setmode( $tx80211, 1 );

if( wtinj_getmode( $tx80211 ) != 1 ){
  ok(0);
}

ok(1);
