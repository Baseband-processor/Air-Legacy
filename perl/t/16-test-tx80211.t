#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
# simple test utility for tx80211_getcardlist function

use strict;
no warnings;

use Data::Dumper qw( Dumper );
use Test::More tests => 1;

use Air::Lorcon2 qw( :lorcon );

my $Cardlist = Dumper( tx80211_getcardlist() );
if ( undef( @{  $Cardlist  } ) ){
  fail("16-test-tx80211.t");
}else{
  ok 1;
  }
