#!/usr/bin/perl

use strict;
use Air::Lorcon2 qw( :lorcon );
use Data::Dumper qw( Dumper );
print Dumper( Air::Lorcon2::lorcon_list_drivers() );
print "insert your driver name: ";
my $driver = <STDIN>;
chomp $driver;


my $drv = lorcon_find_driver( $driver ) or die $!;
my $lorcon = Air::Lorcon2::lorcon_create("wlo1", $drv ) or die $!;

my $packet = "\x00\x00\x00\x00\x00\x00";

if( Air::Lorcon2::lorcon_open_injmon( $lorcon ) == -1 || Air::Lorcon2::lorcon_open_injmon( $lorcon ) == -255 ){	
     die $!; # open monitor mode and injection mode failed
}
print Air::Lorcon2::lorcon_send_bytes($lorcon, length($packet), \$packet);


