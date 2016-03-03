package SpamReport::Exim::DB;
use SpamReport::Data;

use strict;
use warnings;

use DB_File;
use Tie::File;
use Symbol ();
use IO::File;
use Fcntl qw(:flock O_RDWR O_RDONLY O_WRONLY O_CREAT);

use vars qw/$VERSION/;
$VERSION = '2016022601';

my $db_dir = '/var/spool/exim/db';
my $open_dbs = {};

sub open {
    my ($db_name) = @_;

    my $db_file = $db_dir . '/' . $db_name;
    my $lock_file = $db_file . '.lockfile';

    return undef if exists $open_dbs->{$db_name};

    #die "Could not open $lock_file" if ( ! -r $lock_file );
    my $lock_file_fh = Symbol::gensym();
    sysopen($lock_file_fh, $lock_file, O_RDONLY|O_CREAT, 0640) or die "Could not lock database $db_name: $!\n";

    flock $lock_file_fh, LOCK_SH or die "Could not flock() lockfile $lock_file: $!\n";

    tie my %db_hash, 'DB_File', $db_file or die "Could not open $db_file: $!\n";

    $open_dbs->{$db_name}{'lock_fh'} = $lock_file_fh;
    $open_dbs->{$db_name}{'tie_hash'} = \%db_hash;

    1;
}

sub read {
    my ($db_name, $sub_ref) = @_;

    die "Attempted to read non-opened database $db_name" if not exists $open_dbs->{$db_name};
    die "Undefined reference to parser subroutine" if (not defined $sub_ref or ref $sub_ref ne 'CODE');

    while ( my ($key, $value) = each %{$open_dbs->{$db_name}{'tie_hash'}} ) {
        $key =~ s/\x00$//;

        &{$sub_ref}($key, $value);
    }

    1;
}

sub close {
    my ($db_name) = @_;

    return undef if not exists $open_dbs->{$db_name};
    undef $open_dbs->{$db_name}{'tie_hash'};
    untie $open_dbs->{$db_name}{'tie_hash'};
    close $open_dbs->{$db_name}{'lock_fh'};
    delete $open_dbs->{$db_name};

    1;
}

1;
} # end module SpamReport::Exim::DB
