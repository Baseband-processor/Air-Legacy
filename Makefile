C_LORCON_DIR=C
PERL_NET_LORCON_DIR=perl
TMP_INSTALL_DIR=${PWD}/usr
default: all
clean:
	(cd $(C_LORCON_DIR); make clean) && \
	(cd $(PERL_NET_LORCON_DIR); make clean)
all: CT perlT
CT:
	(cd ./C && chmod 755 ./configure && ./configure --prefix=$(TMP_INSTALL_DIR) && make all && make install)
perlT:
	(cd ./$(PERL_NET_LORCON_DIR) && PERL_MM_OPT='LIBS="-L'"$(TMP_INSTALL_DIR)/lib"'" \  INC="-I'"$(TMP_INSTALL_DIR)/include"'"' \
        perl Makefile.PL \
 && INSTALL_BASE=$(TMP_INSTALL_DIR) && make install )
