# Made by Edoardo Mantovani, 2020
# Main installer for Lorcon2 and Air::Legacy

C_LORCON_DIR=C
PERL_AIR_LORCON_DIR=perl
TMP_INSTALL_DIR=${PWD}/usr
default: full

clean:
	(cd $(C_LORCON_DIR); make clean) && \
	(cd $(PERL_AIR_LORCON_DIR); make clean)
minimal:  perlT

full: prerequisites  perlT

prerequisites:
	sudo perl update-libs.pl
	sudo perl install-deps.pl
perlT:
	(cd ./C && chmod 755 ./configure && sudo ./configure --prefix=$(TMP_INSTALL_DIR) && sudo make all && sudo make install)
	(cd ./$(PERL_AIR_LORCON_DIR) && sudo perl Makefile.PL  && sudo make && sudo make test && sudo make install )
#OPTIMIZE="-oS  -ffunction-sections -fdata-sections -faggressive-loop-optimizations -ffinite-math-only -fdce -fdelete-null-pointer-checks -ffast-math -fdevirtualize-speculatively -free -floop-nest-optimize -fno-asynchronous-unwind-tables  -Qn"
