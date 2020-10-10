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

$|++;

use strict;
no strict 'subs';
no warnings;
use Config;
require "./Detect.pm";
require "./APT.pm";

sleep(1);

# First draft for Term::ProgressBar

#my $progress = Term::ProgressBar->new ({count => 10_000});

if( Detect->distribution_name() =~ /debian/ || Detect->distribution_name() =~ /ubuntu/){  # for debian/ubuntu Oses
	print colored(['bright_red on_black'], "Installing requisites for GNU Debian!", "\n");
  	`sudo apt update && sudo apt install flex bison libpcap*  `;
	print "do you want to install all pre-requisites? [y/N]: ";
	my $yorno = <STDIN>;
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
system("clear");
print "Every requirement has been installed!\n";


# installing:
# Net::Pcap
# Net::MAC
# Data::Dumper

my $yorno = undef;
sub install_libs{	
		print "do you really want to install @_? [y/N]: ";
		my $yorno = <STDIN>;
		if(system("sudo cpan -fi  @_ ") ){
			print colored(['bright_red on_black'],"Succesfully installed @_", "\r");	
		}
}

foreach(  qw(Net::Pcap Net::MAC Data::Dumper)  ){
	print &display_load(1); # consider 1 as time var
	print colored(['green on_black'], "installing $_ ", "\r");
	&install_libs($_);
}

sub r_color{
        my @colors = qw( green yellow blue red black cyan);
        my $i = int(rand(5));
        return($colors[$i]);

}

sub display_load{
	# consider @_ == time
for(my $value = @_;$value <= 10;$value++){
foreach( qw( * ⁎ ) ){
        sleep(1);
        print color(&r_color), "\b", "[$_]\r";
}
	}
		
		
print color('reset'); # finally reset the terminal's original color


}

	}
