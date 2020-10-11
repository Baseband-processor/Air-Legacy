# Made by Edoardo Mantovani, 2020
# Main installer for Lorcon2 and Air::Lorcon2

C_LORCON_DIR=C
PERL_AIR_LORCON_DIR=perl
TMP_INSTALL_DIR=${PWD}/usr
default: minimal
clean:
	(cd $(C_LORCON_DIR); make clean) && \
	(cd $(PERL_AIR_LORCON_DIR); make clean)
minimal:  perlT

full: prerequisites  perlT

prerequisites:
	sudo perl install-deps.pl
perlT:
	(cd ./C && chmod 755 ./configure && ./configure --prefix=$(TMP_INSTALL_DIR) && make all && make install)
	(cd ./$(PERL_AIR_LORCON_DIR) && sudo perl Makefile.PL  && sudo make && sudo make test && sudo make install )
#OPTIMIZE="-oS  -ffunction-sections -fdata-sections -faggressive-loop-optimizations -ffinite-math-only -fdce -fdelete-null-pointer-checks -ffast-math -fdevirtualize-speculatively -free -floop-nest-optimize -fno-asynchronous-unwind-tables  -Qn"
