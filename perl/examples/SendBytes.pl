#!/usr/bin/perl

use strict;
use Air::Lorcon2 qw( :lorcon );
use Data::Dumper qw( Dumper );
print Dumper(  lorcon_list_drivers() );
print "insert your driver name: ";
my $driver = <STDIN>;
chomp $driver;


my $drv = lorcon_find_driver( $driver ) or die $!;
my $lorcon =  lorcon_create("wlo1", $drv ) or die $!;

my $packet = "\x00\x00\x00\x00\x00\x00";

if(  lorcon_open_injmon( $lorcon ) == -1 ||  lorcon_open_injmon( $lorcon ) == -255 ){	
     die $!; # open monitor mode and injection mode failed
}
print  lorcon_send_bytes($lorcon, length($packet), \$packet);


