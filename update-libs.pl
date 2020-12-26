# Made by Edoardo Mantovani, 2020
# Simple ExtUtils::MakeMaker updater

no strict 'subs';

sub BEGIN{


open STDERR, '>/dev/null';
system( "sudo cpan -u ExtUtils::MakeMaker" );

close(STDERR);
}
