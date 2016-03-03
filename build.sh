#!/bin/bash

PERL5LIB="${PWD}/lib/perl5${PERL5LIB+:}${PERL5LIB}"; export PERL5LIB;
PERL_LOCAL_LIB_ROOT="${PWD}${PERL_LOCAL_LIB_ROOT+:}${PERL_LOCAL_LIB_ROOT}"; export PERL_LOCAL_LIB_ROOT;
PERL_MB_OPT="--install_base \"${PWD}\""; export PERL_MB_OPT;
PERL_MM_OPT="INSTALL_BASE=${PWD}"; export PERL_MM_OPT;

perl -lne '
BEGIN{
    $out=0;
}

use File::Path qw(make_path);
use File::Basename;
use Scalar::Util qw(openhandle);

if (/^package ([^;]+)/){
    $out=1;
    chomp($mname=$1);
    ($modpath = $mname) =~ s|::|/|g;
    $modpath="lib/perl5/" . $modpath . ".pm";
    make_path(dirname($modpath));
    open $fh, ">", $modpath;
}

if (/#\s*(end.*\Q$mname\E|end main package)$/) {
    $out=0;
    close $fh unless ($1 eq "end main package");
}

if (/^__END__/) {
    $out=1;
}

if ($out){
    print $fh $_;
}

if (openhandle($fh) && eof) {
    close $fh;
}' spamreport.slim.pl

mv lib/perl5/SpamReport.p{m,l}

cpanm -L ./ --exclude-vendor --no-man-pages --installdeps ./

rm -rfv man/

perl bin/fatpack trace lib/perl5/SpamReport.pl
perl bin/fatpack packlists-for $(cat fatpacker.trace) > packlists
#perl bin/fatpack tree fatlib $(cat packlists)
(echo -e "#!/usr/bin/perl\n"; perl bin/fatpack file 2>/dev/null; cat lib/perl5/SpamReport.pl) > spamreport

cp lib/perl5/Geo/ipscountry.dat .
