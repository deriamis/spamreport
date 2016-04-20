export PERL5LIB := ${PWD}/lib${PERL5LIB+:}${PERL5LIB}:${PWD}/lib/perl5
export PERL_LOCAL_LIB_ROOT := ${PWD}${PERL_LOCAL_LIB_ROOT+:}${PERL_LOCAL_LIB_ROOT}
export PERL_MB_OPT := --install_base "${PWD}"
export PERL_MM_OPT := INSTALL_BASE=${PWD}
ASSETS=build/.spamreport/ipscountry.dat build/.spamreport/ip.gif build/.spamreport/cc.gif

.PHONY: deps all install clean distclean lib

all:: lib build/spamreport $(ASSETS)

help::
	@echo "make                 # build spamreport"
	@echo "make clean           # remove all but the final build files"
	@echo "make distclean       # remove all generated files"
	@echo "make install         # copy GeoIP assets to /root/bin"
	@echo
	@echo "NB. some lengthy cpanm installs are required to build,"
	@echo "so 'make distclean' should be used sparingly."

install:: $(ASSETS)
	cp -pv $(ASSETS) /root/bin/

clean::
	rm -rfv build packlists fatlib

distclean:: clean
	rm -rfv man
	find $(PWD)/bin/ -mindepth 1 -maxdepth 1 -newer bin/.timestamp -exec rm -rfv {} \;
	find $(PWD)/lib/perl5/ -mindepth 1 -maxdepth 1 -newer lib/.timestamp -exec rm -rfv {} \;
	rm -fv $(PWD)/bin/.timestamp $(PWD)/lib/.timestamp
	rm -fv fatpacker.trace lib/perl5/ok.pm lib/perl5/SpamReport.pl lib/perl5/SpamReport.pm

lib/.timestamp bin/.timestamp:
	touch $@

lib: bin/.timestamp lib/.timestamp
	mkdir -pv $@/perl5
	make depend

depend:: spamreport.slim.pl deps.pl
	perl bin/cpanm -L ./ --exclude-vendor --no-man-pages --installdeps ./

lib/perl5/SpamReport.pl: spamreport.slim.pl deps.pl
	perl deps.pl $<
	mv lib/perl5/SpamReport.pm lib/perl5/SpamReport.pl

bin/fatpack:
	perl bin/cpanm -L ./ --exclude-vendor --no-man-pages App::FatPacker App::cpanminus

build/spamreport: lib lib/perl5/SpamReport.pl bin/fatpack
	mkdir -p build/.spamreport
	perl bin/fatpack trace lib/perl5/SpamReport.pl 2>/dev/null
	perl bin/fatpack packlists-for $$(cat fatpacker.trace) > packlists
	perl bin/fatpack tree $$(cat packlists)
	(/bin/echo -e "#!/usr/bin/perl\n"; perl bin/fatpack file 2>/dev/null; cat lib/perl5/SpamReport.pl) > $@
	perl -i -pe 'if (/\$$module_dir = __FILE__/) { print; $$_ = q($$module_dir = "/root/bin/.spamreport/";) }' build/spamreport
	perl -i -pe 's|\$$fatpacked{"perl5/|\$$fatpacked{"|g' build/spamreport
	chmod +x $@
	rm -rfv man

build/.spamreport/ipscountry.dat: lib/perl5/Geo/ipscountry.dat
	cp $< $@

build/.spamreport/ip.gif: lib/perl5/IP/Country/Fast/ip.gif
	cp $< $@

build/.spamreport/cc.gif: lib/perl5/IP/Country/Fast/cc.gif
	cp $< $@

