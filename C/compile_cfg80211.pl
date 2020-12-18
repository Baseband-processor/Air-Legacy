#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020
# search for cfg80211.h and compile its control header

my $dir;

sub BEGIN{

use File::Find;

sub filegrep {
    my ($regex, $file) = @_;
    open my $FH, '<', $file or die $!;
    while (<$FH>) {
     return 1 if /$regex/;
    }
    return 0;
}


my @found;
sub findfile {
    my $file = $_;
    my $fullpath = $File::Find::name;
    if (filegrep(qr/regex/, $file)) {
    push @found, $fullpath;
    }
}


find(\&findfile, "cfg80211.h");

}

sub END{



}
