#!/usr/bin/perl
# Made by Edoardo Mantovani, 2020

use strict;
use warnings;
use App::Cpan;

open STDERR, '>/dev/null';
App::Cpan->run( @ARGV );

close(STDERR);

#END
