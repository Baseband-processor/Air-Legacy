# Made by Edoardo Mantovani, 2020
# test list drivers function


use strict;
no strict 'subs';
no warnings;
use Test;
BEGIN { plan tests => 1 };
use Air::Legacy qw(:lorcon);
my $cards = ( lorcon_list_drivers() );



  
