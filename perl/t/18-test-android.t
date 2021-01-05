# Made by Edoardo Mantovani, 2020
# this test reveals if the os is android and testif it's is possible to use lorcon's capabilities

use strict;
no strict 'refs';
use Config;
if( $Config{osname} =~ "android"){
  use Test::More skip_all => "OS is not android!";
}else{
  ok 1;
}
