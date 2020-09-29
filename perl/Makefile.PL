#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
# 1.01: Rewrited entirely the makefile and included XS::Install instead of ExtUtils..


no strict;
use warnings;
use XS::Install;

write_makefile(
   NAME => 'Air::Lorcon2',
   LICENSE => 'perl',
# AUTHOR => 'Edoardo Mantovani aka Baseband',
   DEFINE => '',
   VERSION_FROM => 'lib/Air/Lorcon2.pm',
   LIBS => '-llorcon2',
   INC => '-I/include -I/usr/include -I/usr/local/include',
   BIN_DEPS  => [ "Net::MAC", "Net::Pcap" ],
     
);

# NOTE: Net::Pcap is required only for tests
