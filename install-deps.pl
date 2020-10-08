#!/usr/bin/perl

# Detect OS and Install deps for Air::Lorcon2
# Made by Edoardo Mantovani, 2020

# PRE-version 1.25: added better (and more intuible) front-end graphic
system("clear");

# redirect error output from STDERR in /dev/null 
open STDERR, ">/dev/null";


use Term::ANSIColor;

sub install_libs{	
	my $current_lib = @_;
		if(system("sudo cpan install $current_lib", ">null") ){
			print "Succesfully installed $current_lib\r";	
		}
}


BEGIN{

# set the screen style
print color("red on_black");
# define Air::Lorcon2 logo

my $file = "logo.txt";
open (my $logo, $file) or die "Please, don't delete the logo.txt file!\n";

while( my $line = <$logo> )  {   
    print $line;  
    sleep(1);  # Put a timeout
    last if $. == 0;
}

close ($logo);

sleep(2);
}

END {

# installing libraries and related perl modules

use strict;
no strict 'subs';
no warnings;
use Config;
require "./Detect.pm";


sleep(1);

# create process running in background 

my $process = fork();
unless( $process ){

if( Detect->distribution_name() =~ /debian/ || Detect->distribution_name() =~ /ubuntu/){  # for debian/ubuntu Oses
  	my $comm = `sudo apt update && sudo apt install flex bison libpcap* dh-autoreconf`;

  }    
  
  elsif( Detect->distribution_name() =~ "fedora" || Detect->distribution_name() =~ "centos" ||  Detect->distribution_name() =~ "rhel" ){ # for Fedora/CentOS/RHEL
    system("sudo yum install flex bison libpcap* dh-autoreconf");
  }elsif( Detect->distribution_name() =~ "openSUSE" ){
    system("sudo zypper install flex bison libpcap* dh-autoreconf", ">null");
  }elsif( Detect->distribution_name() =~ "Mageia" ){
    system("sudo urpmi flex bison libpcap* dh-autoreconf");
  }elsif( Detect->distribution_name() =~ "Alpine"){
    system("sudo apk add flex bison libpcap* dh-autoreconf");  
  
  }else{
    print "every dependencies accomplished!\n";
  
}
exit();
			}

wait();
print "Every requirement has been installed!\n";


# installing:
# Net::Pcap
# Net::MAC
# Data::Dumper

foreach(  qw(Net::Pcap Net::MAC Data::Dumper)  ){
	print "installing $_\r";
	&install_libs($_);
}

print color('reset'); # finally reset the terminal's original color


}

