# Made by Edoardo Mantovani, 2020
# see if lorcon is installed by checking the "get_version" func, this will return the constant LORCON_VERSION

use Test;

BEGIN { plan tests => 5 };

use Air::Lorcon2; 
if(undef( Air::Lorcon2::lorcon_get_version() ) ){
  return -1;
}

ok(1);
