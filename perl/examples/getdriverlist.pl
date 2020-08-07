#!/usr/bin/perl

# return all driver from the lorcon_list_driver and try to use the best with lorcon_

use strict;
use warnings;
use Data::Dumper qw( Dumper );
use Net::Lorcon2 qw( :subs );

my @Avaiable_cards = Net::Lorcon2::lorcon_list_drivers();
print Dumper(\@Avaiable_cards);

