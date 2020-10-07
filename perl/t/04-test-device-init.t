#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
# test list drivers function

BEGIN{

use strict;
no strict 'subs';
no warnings;
use Test;
BEGIN { plan tests => 1 };
use Air::Lorcon2 qw(:lorcon);
use Data::Dumper;
my $cards = Dumper( lorcon_list_drivers() );
if( undef( $cards ) ){
  ok(0);
}else{
  ok(1);
}

  }
