# Made by Edoardo Mantovani, 2020
# Simple ExtUtils::MakeMaker updater

no strict 'subs';

sub BEGIN{

use App::Cpan;
open STDERR, '>/dev/null';
App::Cpan->run( "-u ExtUtils::MakeMaker" );

close(STDERR);
}
