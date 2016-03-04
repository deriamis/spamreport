#! /usr/bin/env perl
use File::Path qw(make_path);
use File::Basename;
use Scalar::Util qw(openhandle);
use common::sense;

my ($modpath, $modname, $fh);
my $out = 0;

for (<>) {
    if (/^package ([^;]+)/){
        $out=1;
        chomp($modname=$1);
        ($modpath = $modname) =~ s|::|/|g;
        $modpath="lib/perl5/" . $modpath . ".pm";
        make_path(dirname($modpath));
        open $fh, ">", $modpath or die "Can't open $modpath for writing : $!";
    }

    if (/#\s*(end.*\Q$modname\E|end main package)$/) {
        $out=0;
        close $fh unless ($1 eq "end main package");
    }

    if (/^__END__/) {
        $out=1;
    }

    if ($out){
        print {$fh} $_;
    }
}
