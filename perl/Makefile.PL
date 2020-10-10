#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
# Main installer for Air::Lorcon2

use strict;
no strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
   NAME => 'Air::Lorcon2',
   LICENSE => 'BSD2',
   AUTHOR => 'Edoardo Mantovani aka Baseband',
   DEFINE => '',
   VERSION_FROM => 'lib/Air/Lorcon2.pm',
   LIBS => ['-L/lib -L/usr/lib -L/usr/local/lib -llorcon2'],
   INC => '-I/include -I/usr/include -I/usr/local/include',
   PREREQ_PM => {
      Net::MAC =>  0,
      Net::Pcap => 0,
      Data::Dumper => 0,
  },
);

# NOTE: Net::Pcap is required only for tests

## END ##
