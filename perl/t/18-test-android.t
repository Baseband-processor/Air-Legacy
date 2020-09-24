#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
# this test reveals if the os is android and testif it's is possible to use lorcon's capabilities

use strict;
no strict 'refs';

use Test;

BEGIN{ plan tests => 1 };
use Config;

if( $Config{osname} =~ "android){
  # detect if it's possible to use tcpdump
  if (!`tcpdump -v` ){
    ok(0);
    }
  }else{ 
    ok(1);
    }
