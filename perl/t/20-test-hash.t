# Made by Edoardo Mantovani, 2020
# Main test for using Air::Legacy crypto-tools

use strict;
use Test;
BEGIN{ plan tests => 1 };
use Air::Legacy qw(:crypto);

# craft sha1_context and sha1_hmac_context

my $sha1_init = sha1_meta();
my $hmac_init = sha1_hmac_meta();


# test sha1
sha1_process( $sha1_init, 255 );


# test hmac
my $key = rand(100);
sha1_hmac_starts( $hmac_init, $key, length( $key ) );

ok(1);
