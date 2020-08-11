#!/usr/bin/perl

# try to send malicious bytes though Lorcon2

use strict;
use warnings;

my $interface = 'wlo1';
my $driver    = 'madwifing';

use Air::Lorcon2 qw( :subs );

# WIP
