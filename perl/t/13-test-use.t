#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
# simple test for lorcon export

use strict;
use warnings;
use Test;
BEGIN { plan tests => 1 };
use Air::Legacy qw( :lorcon ); #test without subs
ok(1);
