#!/usr/bin/perl
# Detect OS and Install deps for Air::Lorcon2
# Made by Edoardo Mantovani, 2020
# version 1.35: added APT interface
# PRE-version 1.25: added better (and more intuible) front-end graphic
#use threads;


use Term::ANSIColor;

BEGIN{
# set the screen style

# define Air::Lorcon2 logo
my $file = "logo.txt";
open (my $logo, $file) or die "Please, don't delete the logo.txt file!\n";
# re-clear the screen
sleep(2);
while( my $line = <$logo> )  {   
    print $line;  
    last if $. == 0;
}
close($logo);

use Time::HiRes qw(usleep);

my $text = "
Air::Lorcon2: A fast, portable and efficient library based on Lorcon2. Written in XS for perl penetration tester and wireless-security experts";

my $copyright = "
Copyright (C) 2020 by Edoardo Mantovani, aka BASEBAND


This library is free software;  


you can redistribute it and/or modify it under the same terms as Perl itself, either Perl version 5.8.8 or, at your option, any later version of Perl 5 you may have available.";

foreach( $text =~/./g ){
	print $_;
	select()->flush(); # flush STDIN
	usleep(111111);
	}

print "\n";
foreach( $copyright =~/./g ){
	print $_;
	select()->flush(); # flush STDIN
	usleep(111111);
	if($_ eq "D"){
		print "\n";
		}
	}
print "\n";

}

END {
# installing libraries and related perl modules
$|++;
use strict;
no strict 'subs';
no strict 'refs';
no warnings;

require "./include/Processes.pm";
require "./include/Detect.pm";

# run the processes in Background
my $process = Proc::Simple->new(); 

$process->start( sub {
if( Detect->distribution_name() =~ /debian/ || Detect->distribution_name() =~ /ubuntu/){  # for debian/ubuntu Oses
	require "./include/APT.pm";
	my $apt = Linux::APT->new();
	print colored(['bright_red on_black'], "\nInstalling requisites for GNU Debian!", "\n");
	# for first thing update the Debian Repositories
	$apt->update();
	# install all pre-requisites
	$apt->install( "flex", "bison", "libpcap-dev" ); # Equivalent of `apt update && apt install flex bison libpcap-dev`;
	# libpcap is a special case, we will use libpcap-dev package for installing it as dep.
  }
  elsif( Detect->distribution_name() =~ "fedora" || Detect->distribution_name() =~ "centos" ||  Detect->distribution_name() =~ "rhel" ){ # for Fedora/CentOS/RHEL
    print colored(['bright_red on_black'], "Installing requisites for GNU  Fedora!", "\n");
    system("sudo yum install flex bison libpcap*  ");
  }elsif( Detect->distribution_name() =~ "openSUSE" ){
    print colored(['bright_red on_black'], "Installing requisites for GNU  SUSE!", "\n");
    system("sudo zypper install flex bison libpcap*  ");
  }elsif( Detect->distribution_name() =~ "Mageia" ){
    print colored(['bright_red on_black'], "Installing requisites for GNU Mageia!", "\n");
    system("sudo urpmi flex bison libpcap*  ");
  }elsif( Detect->distribution_name() =~ "Alpine"){
     print colored(['bright_red on_black'], "Installing requisites for Alpine Linux!", "\n");
    system("sudo apk add flex bison libpcap*  ");  
  }
  	print "\nEvery requirement has been installed!\n";
  	});

#$process->kill();

sleep(3);

# installing:
# Net::Pcap


sub display_load{
	# consider @_ == time
for( my $value = @_; $value <= 10; $value++){
foreach( qw( * ⁎ ) ){
        sleep(1);
        print "\b", "[$_] ● installing ●\r";
}
	}
	  }

my $CPAN_file = 'install-module.pl'; 
foreach(  qw(Net::Pcap Net::MAC )  ){
	print &display_load(10);
	my $comm =  `sudo perl $CPAN_file -fi $_ `;
	$comm = undef; # cancel $comm content
}
	

sleep(2);

#$process->kill();



print color('reset'); # finally reset the terminal's original color
}
	
