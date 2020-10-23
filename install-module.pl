#!/usr/bin/perl
# Made by Edoardo Mantovani, 2020

use strict;
use warnings;
use App::Cpan;
#require "./include/Processes.pm";

#my $process = Proc::Simple->new();

#$process->start( sub {
  App::Cpan->run( @ARGV );
 # });
  
#END
