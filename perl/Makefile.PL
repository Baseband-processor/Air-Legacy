#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
# Main installer for Air::Legacy

use strict;
no strict 'refs';
no strict 'subs';
use warnings;
use ExtUtils::MakeMaker;

my @optimize = (OPTIMIZE => );

WriteMakefile(
   NAME => 'Air::Legacy',
   LICENSE => 'BSD2',
   AUTHOR => 'Edoardo Mantovani aka Baseband',
  # CCFLAGS        => '-Wall -std=c99',
  # OPTIMIZE       => '-oS  ',
   DEFINE => '',
   VERSION_FROM => 'lib/Air/Legacy.pm',
   LIBS => ['-L/lib -L/usr/lib -L/usr/local/lib -llorcon2'],
   INC => '-I/include -I/usr/include -I/usr/local/include',
   PREREQ_PM => {
      Net::MAC =>  0,
      Net::Pcap => 0,
  },
);

# NOTE: for now the OPTIMIZE and the CCFLAGS are flawed, will be updated in future

## END ##
