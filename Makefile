C_LORCON_DIR=C
C_LIBNL_DIR=libnl
PERL_AIR_LORCON_DIR=perl
TMP_INSTALL_DIR=${PWD}/usr
default: all
clean:
	(cd $(C_LORCON_DIR); make clean) && \
	(cd $(PERL_AIR_LORCON_DIR); make clean)
all: CT perlT
CT:
	echo "INSTALLING LIBNL DEPENDENCY\n"
	(cd ./libnl && chmod +x autogen.sh && ./autogen.sh && ./configure --prefix=$(TMP_INSTALL_DIR) && make all && make install)
	echo "INSTALLING LORCON C LIBRARY\n"
	(cd ./C && chmod 755 ./configure && ./configure --prefix=$(TMP_INSTALL_DIR) && make all && make install)
perlT:
	(cd ./$(PERL_AIR_LORCON_DIR) && sudo perl Makefile.PL  && make && make test && make install )
