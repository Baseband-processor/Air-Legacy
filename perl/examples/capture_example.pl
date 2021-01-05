# Made by Edoardo Mantovani, 2020

# perl version of capture_example.c

use strict;
use warnings;

use Air::Legacy qw( :lorcon );

# defining our packet disassembly sub

sub apitest_packet_hdlr{
  my ( $context, $packet, $user ) = @_;
  my $dot;
  printf("apitest - %s drv %s got packet len %d\n", lorcon_get_capiface( $context ), lorcon_get_driver_name( $context ), length( $packet ) );
    
  my $len = lorcon_packet_to_dot3( $packet, \$dot );
  
  if( ! $len || undef( $len ) ){
    die "error with $len var!\n";
    }
    
	printf("dot3 length %d\n", $len);

	lorcon_packet_free($packet);

}

BEGIN{
  use Data::Dumper qw( Dumper );
  sleep(1);
  # print supported drivers list
  print Dumper( lorcon_list_drivers() );
  my $choose = <STDIN>;
  chop( $choose );
  my $drv = lorcon_find_driver( $choose );
  if( ! $drv ){
    die("driver error!\n");
  }
  # detect wireless interface name
  
  use Net::Pcap qw( pcap_lookupdev );
  my $pcap_err = '';
  my $pcap_dev = pcap_lookupdev( \$pcap_err );
  # create lorcon
  my $lorcon = lorcon_create(  $pcap_dev, $drv );
  
  # open inject and monitor mode
  lorcon_open_injmon( $lorcon );

  # free the driver list
  lorcon_free_driver_list( $drv );
  
  # start looping a packet
 	
  lorcon_loop( $lorcon , 0, &apitest_packet_hdlr, undef);

  lorcon_free( $lorcon );


}


# END
