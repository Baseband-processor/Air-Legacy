use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
   NAME => 'Air::Lorcon2',
   LICENSE => 'perl',
   AUTHOR => 'Edoardo Mantovani aka Baseband',
   DEFINE => '',
   VERSION_FROM => 'lib/Air/Lorcon2.pm',
   LIBS => ['-L/lib -L/usr/lib -L/usr/local/lib -llorcon2'],
   INC => '-I/include -I/usr/include -I/usr/local/include',
   MIN_PERL_VERSION => '5.22.1',
   PREREQ_PM => {
      Net::MAC =>  0,
      Net::Pcap => 0,
  },
);

# NOTE: Net::Pcap is required only for tests
