#!/usr/bin/perl

# Detect OS and Install deps for Air::Lorcon2
# Made by Edoardo Mantovani, 2020

# PRE-version 1.1: added better (and more intuible) front-end graphic

BEGIN{

use strict;
use warnings;
use Config;
use Term::ANSIColor;
use Linux::Distribution qw(distribution_name);

# define Air::Lorcon2 logo

my $logo = << "end_logo";

  ___  _          _                                _____ 
 / _ \(_)     _ _| |                              / __  \
/ /_\ \_ _ __(_|_) |     ___  _ __ ___ ___  _ __  `' / /'
|  _  | | '__|   | |    / _ \| '__/ __/ _ \| '_ \   / /  
| | | | | |   _ _| |___| (_) | | | (_| (_) | | | |./ /___
\_| |_/_|_|  (_|_)_____/\___/|_|  \___\___/|_| |_|\_____/


end_logo

print color("green"), "Your Operating system is $Config{osname}\n";
print colored ($logo, 'bold red on_black');



sleep(1);

# create process running in background 

my $process = fork();
unless( $process ){

if( distribution_name() =~ /debian/ || distribution_name() =~ /ubuntu/){  # for debian/ubuntu Oses
  	system("sudo apt update ");
	system("sudo apt install flex bison libpcap* dh-autoreconf");

  }    
  
  elsif( distribution_name() =~ "fedora" || distribution_name() =~ "centos" ||  distribution_name() =~ "rhel" ){ # for Fedora/CentOS/RHEL
    system("sudo yum install flex bison libpcap* dh-autoreconf");
  }elsif( distribution_name() =~ "openSUSE" ){
    system("sudo zypper install flex bison libpcap* dh-autoreconf");
  }elsif( distribution_name() =~ "Mageia" ){
    system("sudo urpmi flex bison libpcap* dh-autoreconf");
  }elsif( distribution_name() =~ "Alpine"){
    system("sudo apk add flex bison libpcap* dh-autoreconf");  
  
  }else{
    print "every dependencies accomplished!\n";
  
}
	exit();	
			}

wait();
print "Every requirement has been installed!\n";

print color('reset'); # reset the color


}

exit(1); # EXIT with status 1 (success)
