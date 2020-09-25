#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
# test pure-perl subroutines

use strict;
no strict 'subs';
use Test;
BEGIN{ plan tests => 4 };

use Air::Lorcon2 qw( :lorcon );

if( ! association_reason_codes_HASH() ){
  ok(0);
}else{
  ok(1);
}

if( ! dissociation_reason_codes_HASH() ){
  ok(0);
}else{
  ok(1);
}

if( ! channel_to_frequency_HASH() ){
  ok(0);
}else{
  ok(1);
}

if( ! RMAC_gen() ){
  ok(0);
}else{
  ok(1);
}
