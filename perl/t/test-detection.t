#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
# basic test for finding the driver type

use strict;
no strict 'subs';
use Test;

BEGIN{ plan tests => 1};

use Air::Lorcon2 qw( :lorcon );

my $driver = Detect_Driver();

if(undef ( $driver ) || ( length( $driver) <= 2 ) ){ # Driver name too short
  ok(0);
}

ok(1);
