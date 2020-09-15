#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
use strict;
use warnings;

use Test;
BEGIN{ plan tests => 4 };

use Air::Lorcon2 qw(:lorcon);

my $loop = lorcon_multi_create();

if( undef( $loop ) ) {
  ok(0);
  }else{
  ok(1);
  }

my @interfaces = lorcon_multi_get_interfaces( $loop );


if( undef( @interfaces ) ) {
  ok(0);
  }else{
  ok(1);
  }

ok(1);
  
