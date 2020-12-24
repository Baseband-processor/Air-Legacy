
no strict 'subs';

sub BEGIN{

use App::Cpan;
open STDERR, '>/dev/null';
App::Cpan->run( @ARGV );

close(STDERR);
}

cpan upgrade
