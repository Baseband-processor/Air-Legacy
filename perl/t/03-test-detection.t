#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
# basic test for finding the driver type

use strict;
no strict 'subs';
use Test::More tests => 1;

BEGIN{ use_ok( 'Air::Lorcon2' ); }

use Air::Lorcon2 qw( :lorcon );

my $driver = Detect_Driver();

if( undef( $driver ) ){ 
  fail 0;
}

ok 6;
