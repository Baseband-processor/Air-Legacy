# Made by Edoardo Mantovani, 2020
# Main installer for Lorcon2 and Air::Lorcon2

C_LORCON_DIR=C
C_LIBNL_DIR=libnl
PERL_AIR_LORCON_DIR=perl
TMP_INSTALL_DIR=${PWD}/usr
default: minimal
clean:
	(cd $(C_LORCON_DIR); make clean) && \
	(cd $(PERL_AIR_LORCON_DIR); make clean)
minimal:  perlT

full: prerequisites  perlT

prerequisites:
	sudo cpan -fi Linux::Distribution
	sudo perl install-deps.pl
	sudo cpan -fi Net::Pcap
perlT:
	sudo cpan -fi Net::Pcap
	sudo cpan -fi Net::MAC
	sudo cpan -fi Data::Dumper
	echo "INSTALLING LORCON C LIBRARY\n"
	(cd ./C && chmod 755 ./configure && ./configure --prefix=$(TMP_INSTALL_DIR) && make all && make install)
	(cd ./$(PERL_AIR_LORCON_DIR) && sudo perl Makefile.PL  && make && make test && make install )
