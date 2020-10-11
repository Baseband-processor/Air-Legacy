#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
# Air::Lorcon2's HASHING support

package Air::Lorcon2::Extra;

our $VERSION = '27.75';

use strict;
no strict 'subs';
no strict 'refs';
use warnings;
use base qw(Exporter DynaLoader);

our %EXPORT_TAGS = (
  sha1 => [qw(
    sha1_process
    sha1_update
    sha1_finish
    sha1_starts
    sha1_hmac_starts
    sha1_hmac_update
    sha1_hmac_finish
    sha1_hmac  
  )],
  
);

our @EXPORT = (
  @{ $EXPORT_TAGS{ sha1 } },
);
  
1;
