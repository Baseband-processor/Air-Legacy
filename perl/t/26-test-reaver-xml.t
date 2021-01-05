# Made by Edoardo Mantovani, 2020
# test wps_data_to_json function

use strict;
use warnings;
use Test;
BEGIN{ plan tests => 1 };

use Air::Legacy qw( :lorcon :reaver );

my $random_MAC = Rand_MAC();

my $progress = "30";

# generate LIBWPS_DATA  object
my $libWPS = libwps_meta();

wps_data_to_json( \$random_MAC, \$random_MAC, 1, 3, \"h", $libWPS, \$progress);

ok(1);
