#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
# test lorcon_multi capabilities

# Version 1.25

use strict;
no strict 'subs';
no strict 'refs';
no warnings;

use Test;
BEGIN{ plan tests => 1 };

use Air::Lorcon2 qw(:lorcon);

my $loop = lorcon_multi_create(); # create lorcon_multi_t type
my $interfaces = lorcon_multi_get_interfaces( $loop ) or die("error about interfaces\n)";

my $lorcon = lorcon_multi_interface_get_lorcon( $interfaces ) or die("error getting lorcon\n");


ok(1);
  
