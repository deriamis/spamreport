#!/bin/bash

PERL5LIB="${PWD}/lib/perl5${PERL5LIB+:}${PERL5LIB}"; export PERL5LIB;
PERL_LOCAL_LIB_ROOT="${PWD}${PERL_LOCAL_LIB_ROOT+:}${PERL_LOCAL_LIB_ROOT}"; export PERL_LOCAL_LIB_ROOT;
PERL_MB_OPT="--install_base \"${PWD}\""; export PERL_MB_OPT;
PERL_MM_OPT="INSTALL_BASE=${PWD}"; export PERL_MM_OPT;

perl bin/fatpack trace lib/perl5/SpamReport.pl
perl bin/fatpack packlists-for $(cat fatpacker.trace) > packlists
perl bin/fatpack tree fatlib $(cat packlists)
(perl bin/fatpack file; cat lib/perl5/SpamReport.pl) > spamreport
