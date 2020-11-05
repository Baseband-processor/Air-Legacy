#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
# basic test for finding the driver type

use strict;
no strict 'subs';
use Test::More tests => 2;

BEGIN{ use_ok( 'Air::Legacy' ); }

use Air::Legacy qw( :lorcon );

my $driver = Detect_Driver();

if( undef( $driver ) ){ 
  fail 0;
}

ok 6;
