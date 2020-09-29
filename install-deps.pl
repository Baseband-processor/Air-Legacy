#!/usr/bin/perl

# Detect OS and Install deps for Air::Lorcon2
# Made by Edoardo Mantovani, 2020

BEGIN{


use strict;
use warnings;
use Config;
use Linux::Distribution qw(distribution_name);

print "Your Operating system is $Config{osname}\n";

sleep(1);

if( distribution_name() =~ /debian/ || distribution_name() =~ /ubuntu/){  # for debian/ubuntu Oses
  	system("sudo apt update ");
	system("sudo apt install flex bison libpcap* dh-autoreconf");
	system("cpan -fi XS::Install");
  }    
  
  elsif( distribution_name() =~ "fedora" || distribution_name() =~ "centos" ||  distribution_name() =~ "rhel" ){ # for Fedora/CentOS/RHEL
    system("sudo yum install flex bison libpcap* dh-autoreconf");
    system("cpan -fi XS::Install");
  }elsif( distribution_name() =~ "openSUSE" ){
    system("sudo zypper install flex bison libpcap* dh-autoreconf");
    system("cpan -fi XS::Install");
  }elsif( distribution_name() =~ "Mageia" ){
    system("sudo urpmi flex bison libpcap* dh-autoreconf");
    system("cpan -fi XS::Install");
  }elsif( distribution_name() =~ "Alpine"){
    system("sudo apk add flex bison libpcap* dh-autoreconf");  
    system("cpan -fi XS::Install");
  
  }else{
    print "every dependencies accomplished!\n";
  
}		}
