#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
# test reaver utilities

use strict;
no strict 'refs';
no strict 'subs';
use warnings;

use Test;

BEGIN{ plan tests => 1 };

use Air::Legacy qw( :reaver );

# test struct allocation

my $meta_request = assoc_request_meta();

my $assoc_response = assoc_response_meta();

my $beacon_management = beacon_management_meta();

my $auth_management = auth_management_meta();

my $libwps = libwps_meta();

my $glob = globule_init();

# deinit glob, would be quite similar to $glob = undef
$glob = globule_deinit();

my $packet = "\x00\x00\x00\x00\x00\x00\x00\x00\x00" # NULL packet

my $eapol_packet = build_eapol_start_packet( length( $packet ) );

my $failure_packet = build_eap_failure_packet( length( $packet ) );

my $rand_time = int(rand() );

# finally, inject with reaver

reaver_inject( $packet, length( $packet ), $rand_time );

ok 1;
