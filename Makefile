NTLNAME=ntl-10.5.0
NTLURL=http://www.shoup.net/ntl/$(NTLNAME).tar.gz

WGET=$(shell which wget)
MAKE=$(shell which make)
SED=$(shell which sed)
TAR=$(shell which tar)

helib: ntl
	$(SED) -i 's,\(^CFLAGS =.*\$\),\1 -I$$(HOME)/include,g' src/Makefile
	$(MAKE) -C src

ntl: download-ntl
	cd $(NTLNAME)/src; ./configure DEF_PREFIX=$(HOME) NTL_THREADS=on NTL_THREAD_BOOST=on NTL_EXCEPTIONS=on;
	$(MAKE) -C $(NTLNAME)/src
	$(MAKE) -C $(NTLNAME)/src install

download-ntl:
	$(WGET) $(NTLURL)
	$(TAR) xvfz $(NTLNAME).tar.gz
	
clean:
	-rm -r $(NTLNAME) $(NTLNAME).tar.gz
