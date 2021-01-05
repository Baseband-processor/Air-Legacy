# Made by Edoardo Mantovani, 2020

sub BEGIN{

use strict;
no strict 'subs';
use App::Cpan;

open STDERR, '>/dev/null';
App::Cpan->run( @ARGV );

close(STDERR);

}

