#!/usr/bin/perl

# Detect OS and Install deps for Air::Lorcon2
# Made by Edoardo Mantovani, 2020

# PRE-version 1.25: added better (and more intuible) front-end graphic

system("clear");


use Term::ANSIColor;


BEGIN{

# set the screen style
print color("red on_black");
# define Air::Lorcon2 logo

my $file = "logo.txt";
open (my $logo, $file) or die "Please, don't delete the logo.txt file!\n";

print colored(['bright_red on_black'], "Made by Edoardo Mantovani", "\n");

# re-clear the screen

system("clear");

sleep(2);

while( my $line = <$logo> )  {   
    print $line;  
    last if $. == 0;
}

close($logo);

}

END {

# installing libraries and related perl modules

use strict;
no strict 'subs';
no warnings;
use Config;
require "./Detect.pm";

sleep(1);

if( Detect->distribution_name() =~ /debian/ || Detect->distribution_name() =~ /ubuntu/){  # for debian/ubuntu Oses
  	my $comm = `sudo apt update && sudo apt install flex bison libpcap*  >/dev/null`;

  }
  elsif( Detect->distribution_name() =~ "fedora" || Detect->distribution_name() =~ "centos" ||  Detect->distribution_name() =~ "rhel" ){ # for Fedora/CentOS/RHEL
    system("sudo yum install flex bison libpcap*  >/dev/null");
  }elsif( Detect->distribution_name() =~ "openSUSE" ){
    system("sudo zypper install flex bison libpcap*  >/dev/null ");
  }elsif( Detect->distribution_name() =~ "Mageia" ){
    system("sudo urpmi flex bison libpcap*  >/dev/null");
  }elsif( Detect->distribution_name() =~ "Alpine"){
    system("sudo apk add flex bison libpcap*  >/dev/null");  
  
  }

print "Every requirement has been installed!\n";


# installing:
# Net::Pcap
# Net::MAC
# Data::Dumper
sub install_libs{	
	my $current_lib = @_;
		if(system("sudo cpan install $current_lib >/dev/null") ){
			print colored(['bright_red on_black'],"Succesfully installed $current_lib", "\r");	
		}
}

foreach(  qw(Net::Pcap Net::MAC Data::Dumper)  ){
	print colored(['green on_black'], "installing $_ ", "\r");
	&install_libs($_);
}

print color('reset'); # finally reset the terminal's original color


}

