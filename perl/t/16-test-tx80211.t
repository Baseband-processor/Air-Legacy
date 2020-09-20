#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
# simple test utility for tx80211_getcardlist function

use strict;
no warnings;

use Data::Dumper qw( Dumper );
use Test;
BEGIN{ plan tests => 1 };

use Air::Lorcon2 qw( :lorcon );

if( ! Dumper( tx80211_getcardlist() ) ){
  ok(0);
}else{
  ok(1);
}
