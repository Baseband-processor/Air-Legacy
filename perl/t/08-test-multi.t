#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
# test lorcon_multi capabilities

use strict;
no strict 'subs';
no strict 'refs';
no warnings;

use Test;
BEGIN{ plan tests => 1 };

use Air::Lorcon2 qw(:lorcon);

my $loop = lorcon_multi_create();
my $interfaces = Air::Lorcon2::lorcon_multi_get_interfaces( \$loop );


if( undef( $interfaces ) ) {
  ok(0);
}else{
  ok(1);
  }

my $lorcon = lorcon_multi_interface_get_lorcon( $interfaces );

if( undef( $lorcon ) ) {
  ok(0);
}else{
  ok(1);
}

ok(1);
  
