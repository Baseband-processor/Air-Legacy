#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
# simple test utility for tx80211_getcardlist function and related tx80211 functions

use strict;
no strict 'refs';
no warnings;

use Test::More tests => 1;

use Air::Lorcon2 qw( :lorcon );

tx80211_getcardlist();

my $tx80211 = tx80211_meta();

my $tx80211_packet = tx80211_packet_meta();

# use mode '1'
tx80211_setfunctionalmode( $tx80211, 1 );

tx80211_getmode( $tx80211 );

tx80211_geterrstr( $tx80211 );

tx80211_gettxrate( $tx80211_packet );


# free everything at the end

tx80211_free( $tx80211 );

ok(6);

