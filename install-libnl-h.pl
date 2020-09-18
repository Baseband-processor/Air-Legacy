#!/usr/bin/perl

#### FILE DEPRECATED, FOR NOW NO USES ####

# Made by Edoardo Mantovani, 2020
# This simple script will search for any libnl installation, find the interested headers and modify the Cthxs.h file, inserting the headers

my @libnl;
my $i = 0;

my $Header_F = "./perl/Ctxs.h";
if(! -e $Header_F ){
  die "Could not find Ctxs.h file!\n";
}

my @Interested_H = ( "libnl.h" ); # TODO: add other
my @PossibleDirs = ( "/usr/include/", "/usr/local/include" ); # possible position of header files

foreach ( @PossibleDirs ){
  foreach ( opendir( FOLDER, $PossibleDirs[$i] ) ){
    if( $_ =~ "libnl" ){
      push ( @libnl, $_,  );
  }

  $i++ if ( $i <= $#PossibleDirs );
  }
  	}
  if( undef( @libnl )  or ($#libnl <= 0 ) ){
    die "Error searching the libnl headers, control  the installation!\n";
    }
   
   foreach ( @libnl ){ # append the header sources into the Ctxs.h
      open( HEADER, '>', $Header_F );
      print HEADER $_;
      print HEADER "\n"; # print the return carriage
  
   }
  
close(HEADER);

print "Everything went well, return code: 0\n";
die 1;
