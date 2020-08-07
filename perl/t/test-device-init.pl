use Test;
BEGIN { plan tests => 2 };
use Net::Lorcon2 qw(:subs);
my @cards = lorcon_list_drivers();
if( $#cards < 1 ){
  return -1;
  }else{
  return 1;
  }
  ok(1);
