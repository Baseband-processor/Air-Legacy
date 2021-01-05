# Detect OS and Install deps for Air::Legacy
# Made by Edoardo Mantovani, 2020
# version 1.35: added APT interface
# Version 1.47: added Aircrack-ng library installer interface

use Term::ANSIColor;

my $answ; # our decision for aircrack-ng installation

sub BEGIN{
# set the screen style
print color("bright_red");
# define Air::Lorcon2 logo
my $file = "logo.txt";
open (my $logo, $file) or die "Please, don't delete the logo.txt file!\n";
# re-clear the screen
sleep(2);
while( my $line = <$logo> )  {   
    print $line;  
    usleep(111111);
    last if $. == 0;
}
close($logo);

use Time::HiRes qw(usleep);

print "\n";

my $text = "
Air::Legacy: A fast, portable and efficient library based on Lorcon2, aircrack-ng and pixie-wps, with some cryptographic reinforcement. 
Written in XS for both perl penetration tester and wireless-security experts";

foreach( $text =~/./g ){
	print $_;
	select()->flush(); # flush STDIN
	usleep(111111);
	}

print "\n";

}

sub INIT{
# installing libraries and related perl modules

$|++;
use strict;
no strict 'subs'; # optimize subroutine execution
no strict 'refs';
no warnings 'all';

{
require "./include/Processes.pm";
require "./include/Detect.pm";
}

print color("green"), "Would you like to install also the Aircrack-ng extension? [y/n]: ";
$answ = <STDIN>;
chop($answ);

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
	if( defined( shift ) ){
		$apt->install( "flex");
		$apt->install("bison");
		$apt->install("libpcap-dev");
		$apt->install("linux-libc-dev");
		$apt->install("libnet1-dev");
		if( $answ =~ "y" ){
			$apt->install("build-essential");
			$apt->install("autoconf");
			$apt->install("automake");
			$apt->install("libtool");
			$apt->install("pkg-config");
			$apt->install("libnl-3-dev");
			$apt->install("libnl-genl-3-dev");
			$apt->install("libssl-dev");
			$apt->install("ethtool");
			$apt->install("shtool");
			$apt->install("rfkill");
			$apt->install("zlib1g-dev");
			$apt->install("libpcap-dev");
			$apt->install("libsqlite3-dev");
			$apt->install("libpcre3-dev");
			$apt->install("libhwloc-dev");
			$apt->install("libcmocka-dev");
			$apt->install("hostapd");
			$apt->install("wpasupplicant");
			$apt->install("tcpdump");
			$apt->install("screen");
			$apt->install("iw"); 
			$apt->install("usbutils");
		}
		if( ! `which git` ){
			$apt->install("git");
	}
	}else{
		$apt->install( "flex");
		$apt->install("bison");
		$apt->install("libpcap-dev");
		$apt->install("linux-libc-dev" ); 
		# Equivalent of `apt update && apt install flex bison libpcap-dev linux-libc-dev `;
		# libpcap is a special case, we will use libpcap-dev package for installing it as dep.
		if( $answ =~ "y" ){
			$apt->install("build-essential");
			$apt->install("autoconf");
			$apt->install("automake");
			$apt->install("libtool");
			$apt->install("pkg-config");
			$apt->install("libnl-3-dev");
			$apt->install("libnl-genl-3-dev");
			$apt->install("libssl-dev");
			$apt->install("ethtool");
			$apt->install("shtool");
			$apt->install("rfkill");
			$apt->install("zlib1g-dev");
			$apt->install("libpcap-dev");
			$apt->install("libsqlite3-dev");
			$apt->install("libpcre3-dev");
			$apt->install("libhwloc-dev");
			$apt->install("libcmocka-dev");
			$apt->install("hostapd");
			$apt->install("wpasupplicant");
			$apt->install("tcpdump");
			$apt->install("screen");
			$apt->install("iw"); 
			$apt->install("usbutils");
		}
		if( ! `which git` ){
			$apt->install("git");
		}
  }
  	}
	
  elsif( Detect->distribution_name() =~ "fedora" || Detect->distribution_name() =~ "centos" ||  Detect->distribution_name() =~ "rhel" ){ # for Fedora/CentOS/RHEL
    print colored(['bright_red on_black'], "Installing requisites for GNU  Fedora!", "\n");
    system("sudo yum install flex bison libpcap* libnet-* ");
  }elsif( Detect->distribution_name() =~ "openSUSE" ){
    print colored(['bright_red on_black'], "Installing requisites for GNU  SUSE!", "\n");
    system("sudo zypper install flex bison libpcap*  libnet-*");
  }elsif( Detect->distribution_name() =~ "Mageia" ){
    print colored(['bright_red on_black'], "Installing requisites for GNU Mageia!", "\n");
    system("sudo urpmi flex bison libpcap* libnet-* ");
  }elsif( Detect->distribution_name() =~ "Alpine"){
     print colored(['bright_red on_black'], "Installing requisites for Alpine Linux!", "\n");
    system("sudo apk add flex bison libpcap*  libnet-*");  
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
        print "\b", "[$_] ● installing ● \r";
}
	}
	  }

my $CPAN_file = 'install-module.pl'; 


foreach(  qw(Net::Pcap Net::MAC )  ){
	print &display_load(10);
	my $comm =  `sudo perl $CPAN_file -fi $_ `;
	$comm = undef; # cancel $comm content
	if( $_ eq "Net::Pcap" ){
		chomp(my $yy =<STDIN>);
		$yy ||= "yes\n\n"; 
	}
}
	
	
	
sleep(2);

#$process->kill();



print color('reset'); # finally reset the terminal's original color

print "entering into aircrack-ng installation!\n";
}
	
sub END{


sub install_aircrack(){
	# gather aircrack-ng binary
	# disable STDOUT
	if( -e "/dev/null"){
		open(STDOUT, '>/dev/null');
	}
	`git clone https://github.com/aircrack-ng/aircrack-ng`;
	if( -e "/dev/null"){
		close(STDOUT);
	}
}

if( $answ =~ "y" or lc($answ) =~ "y" ){
	&install_aircrack();
	system("chmod +x aircrack-install && ./aircrack-install");
	}
}
