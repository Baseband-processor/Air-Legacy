#!/usr/bin/perl
# Detect OS and Install deps for Air::Lorcon2
# Made by Edoardo Mantovani, 2020
# version 1.35: added APT interface
# PRE-version 1.25: added better (and more intuible) front-end graphic
#use threads;


use Term::ANSIColor;

BEGIN{
# set the screen style
print color("red on_black");
# define Air::Lorcon2 logo
my $file = "logo.txt";
open (my $logo, $file) or die "Please, don't delete the logo.txt file!\n";
print colored(['bright_red on_black'], "Made by Edoardo Mantovani", "\n");
# re-clear the screen
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
no strict 'refs';
no warnings;
use Config;

require "./include/Processes.pm";
require "./include/Detect.pm";

# run the processes in Background
my $process = Proc::Simple->new(); 

$process->start( sub {
if( Detect->distribution_name() =~ /debian/ || Detect->distribution_name() =~ /ubuntu/){  # for debian/ubuntu Oses
	require "./include/APT.pm";
	my $apt = Linux::APT->new();
	print colored(['bright_red on_black'], "Installing requisites for GNU Debian!", "\n");
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
  	print "Every requirement has been installed!\n";
  	});

#$process->kill();

sleep(3);

# installing:
# Net::Pcap

sub install_libs{	
		if(system("sudo cpan -fi  @_ ") ){
			print colored(['bright_red on_black'],"Succesfully installed @_", "\r");	
		}
}

sub display_load{
	# consider @_ == time
for( my $value = @_; $value <= 10; $value++){
foreach( qw( * ⁎ ) ){
        sleep(1);
        print color(&r_color), "\b", "[$_]\r", color(&r_color), "Installing the required library, loading...\r";
}
	}
	  }

$process->start( sub {
foreach(  qw(Net::Pcap Net::MAC Data::Dumper)  ){
	print &display_load(1); # consider 1 as time var
	print colored(['green on_black'], "installing $_ ", "\r");
	&install_libs($_);
}
	});


sleep(2);

#$process->kill();



print color('reset'); # finally reset the terminal's original color
}
	
