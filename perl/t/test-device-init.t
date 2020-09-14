use Test;
BEGIN { plan tests => 1 };
use Air::Lorcon2 qw(:lorcon);
use Data::Dumper;
my $cards = Dumper( lorcon_list_drivers() );
if(( undef $cards ) ){
  ok(0);
  }else{
  ok(1);
	}
