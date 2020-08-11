#!/usr/bin/perl

# return all driver from the lorcon_list_driver and try to use the best with lorcon_

use strict;
use warnings;
use Data::Dumper qw( Dumper );
use Air::Lorcon2 qw( :lorcon );

my @Avaiable_cards = Air::Lorcon2::lorcon_list_drivers();
print Dumper(\@Avaiable_cards);

