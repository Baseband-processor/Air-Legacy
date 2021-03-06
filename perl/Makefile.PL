
# Made by Edoardo Mantovani, 2020
# Main installer for Air::Legacy



sub BEGIN{

no strict 'subs';
use warnings;
use ExtUtils::MakeMaker;


WriteMakefile(
   NAME => 'Air::Legacy',
   LICENSE => 'BSD2',
   AUTHOR => 'Edoardo Mantovani aka Baseband',
  # CCFLAGS        => '-Wall -std=c99',
  # OPTIMIZE       => '-oS  ',
   'OPTIMIZE' => '-O0', 
   VERSION_FROM => 'lib/Air/Legacy.pm',
   LIBS => ['-L/lib -L/usr/lib -L/usr/local/lib -llorcon2 -laircrack-ng'],
   INC => '-I/include -I/usr/include -I/usr/local/include',
   PREREQ_PM => {
      Net::MAC =>  0,
      Net::Pcap => 0,
      Test::More => 0,
  },

);
# NOTE: for now the OPTIMIZE and the CCFLAGS are flawed, will be updated in future

## END ##

}
