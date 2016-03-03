package File::Nonblock;

use strict;
use warnings;

use vars qw/$VERSION/;
$VERSION = '2016021901';

use English qw( -no_match_vars );
use Scalar::Util qw(openhandle);
use IPC::Open2 qw( open2 );
use IO::Select qw();
use Symbol qw(gensym);
use File::Which qw ( which );

my $lines_per_read = 100;
my $read_timeout = 0;
my $read_buffer_size = 8*1024;
my $MIN_COMPRESS_RATIO = 0.94;
my $gzip = which('gzip');
my $buffer = {};
my $open_files = {};
my $open_handles = {};
my $last_incomplete_line = {};
my $complete_lines = {};

sub update_map {
    my @descriptors = qw(
        pid eof size real_size progress_frac
        prev_progress progress progress_state
        ratio selector read_buffer_size
        bytes_read );
    undef $open_handles;

    for my $file_name ( keys %{ $open_files } ) {
        my $handle = $open_files->{$file_name}{'handle'};
        $open_handles->{$handle}{'name'} = $file_name;

        for my $descriptor (@descriptors) {
            $open_handles->{$handle}{$descriptor} = \$open_files->{$file_name}{$descriptor};
        }
    }

    return 1;
}

sub name {
    my ($file) = @_;
    return $file if ( not ref $file );
    return undef if not ( ref $file eq 'GLOB' );
    return $open_handles->{$file}{'name'} if exists $open_handles->{$file}{'name'};
    return readlink "/proc/$$/fd/" . fileno($file) if openhandle($file);
    return undef;
}

sub open {
    my ($file, $buf_sz) = @_;
    $buf_sz ||= $read_buffer_size;
    die "No file specified" if not $file;

    my $handle = gensym;
    my $file_name = '';

    if ( not ref $file ) {

        return undef if exists $open_files->{$file};
        die "File $file does not exist" if (! -f $file);

        $file_name = $file;

        if ( $file =~ m/\.(gz)$/ ) {

            my ($u_size, $c_size, $ratio) = (0, 0);

            my $child_pid = open my $child, '-|';
            defined $child_pid or die "Can't fork: $!";

            if ( $child_pid ) {
                ($c_size, $u_size, $ratio) = ( split " ", (<$child>)[1] )[0..2];
                $ratio = ($ratio =~ s/%$//) / 100;
                close $child;
            }
            else {
                ($EUID, $EGID) = ($UID, $GID);
                exec $gzip, '--list', $file or die "Could not exec $gzip: $!";
            }

            while ( $ratio < $MIN_COMPRESS_RATIO ) {
                $u_size *= 2;
                $ratio = 1 - ( $c_size / $u_size );
            }


            $open_files->{$file_name}{'real_size'} = $u_size;
            $open_files->{$file_name}{'size'} = $c_size;
            $open_files->{$file_name}{'ratio'} = $ratio;

            $open_files->{$file_name}{'pid'} = open2($handle, undef, $gzip, '-dc', $file)
                or die "Could not fork $gzip: $!";
        }
        else {
            open $handle, '<', $file_name;
            $open_files->{$file_name}{'pid'} = 0;
            $open_files->{$file_name}{'real_size'} = (stat($file))[7];
            $open_files->{$file_name}{'size'} = $open_files->{$file_name}{'real_size'};
            $open_files->{$file_name}{'ratio'} = 0;
        }
    }
    elsif ( ref $file eq 'GLOB' ) {

        die "Passed a closed file handle" if ( !openhandle($file) );

        $file_name = name($file);
        $handle = $file;
        $open_files->{$file_name}{'pid'} = 0;
        $open_files->{$file_name}{'real_size'} = (stat($file))[7];
        $open_files->{$file_name}{'size'} = $open_files->{$file_name}{'real_size'};
        $open_files->{$file_name}{'ratio'} = 0;

        return undef if exists $open_files->{$file_name};
    }
    else {
        die "Unknown argument";
    }

    $open_files->{$file_name}{'selector'} = IO::Select->new();
    $open_files->{$file_name}{'selector'}->add($handle);

    $open_files->{$file_name}{'handle'} = $handle;
    $open_files->{$file_name}{'bytes_read'} = 0;
    $open_files->{$file_name}{'progress'} = 0;
    $open_files->{$file_name}{'prev_progress'} = 0;
    $open_files->{$file_name}{'progress_frac'} = 0;
    $open_files->{$file_name}{'progress_state'} = 'Reading';
    $open_files->{$file_name}{'eof'} = 0;

    @{ $open_files->{$file_name}{'stat'} } = stat($handle);

    $open_files->{$file_name}{'read_buffer_size'} = $buf_sz;
    $buffer->{$file_name} = '';
    vec($buffer->{$file_name}, $buf_sz, 8) = 0;
    $buffer->{$file_name} = '';

    update_map();

    return $read_timeout > 0 ? ( $open_files->{$file_name}{'selector'}->can_read($read_timeout) )[0]
                             : ( $open_files->{$file_name}{'selector'}->can_read )[0];
}

sub stat {
    my ($file) = @_;
    return undef if not $file;

    my $file_name;

    if ( not ref $file ) {
        return undef unless exists $open_files->{$file};
        return stat($file) if ( -r $file );
    }
    elsif ( ref $file eq 'GLOB' ) {
        return undef unless exists $open_handles->{$file};

        $file_name = name($file);
        return undef if not $file_name;

        if ( $open_files->{$file_name}{'pid'} != 0 ) {
            return @{ $open_files->{$file_name}{'stat'} };
        }

        return (stat($file_name))[7] if ( -r $file_name );
    }
    else {
        die "Unknown argument";
    }

    return undef;
}

sub update_size {
    my ($file) = @_;
    return undef if not $file;

    my $file_name = '';

    if ( not ref $file ) {
        return undef if not exists $open_files->{$file};
        return undef if not openhandle($open_files->{$file}{'handle'});
        $file_name = $file;
 
    }
    elsif ( ref $file eq 'GLOB' ) {
        return undef if not exists $open_handles->{$file};
        return undef if not openhandle($file);
        $file_name = name($file);
    }
    else {
        die "Unknown argument";
    }

    my $ref = $open_files->{$file_name};

    $ref->{'real_size'} = $ref->{'bytes_read'} if ( $ref->{'eof'} );
    $ref->{'real_size'} *= 2 if ( $ref->{'bytes_read'} > $ref->{'real_size'} );

    $ref->{'ratio'} = 1 - ( $ref->{'real_size'} / $ref->{'size'} );

    1;
}

sub tell {
    my ($file) = @_;
    return undef if not $file;

    my $file_name;

    if ( not ref $file ) {
        return undef if not exists $open_files->{$file};
        return undef if not openhandle($open_files->{$file}{'handle'});
        $file_name = $file;
    }
    elsif ( ref $file eq 'GLOB' ) {
        return undef if not exists $open_handles->{$file};
        return undef if not openhandle($file);
        $file_name = name($file);
    }
    else {
        die "Unknown argument";
    }

    my $ref = $open_files->{$file_name};
    my $bytes_read = $ref->{'pid'} == 0 ? tell($ref->{'handle'})
                                        : $ref->{'bytes_read'};

    update_size($file) if ( $ref->{'pid'} != 0 );

    return $bytes_read;
}

sub eof {
    my ($file) = @_;
    return undef if not $file;

    my $file_name;

    if ( not ref $file ) {
        $file_name = $file if exists $open_files->{$file};
        return undef if not openhandle($open_files->{$file}{'handle'});
    }
    elsif ( ref $file eq 'GLOB' ) {
        $file_name = name($file);
        return undef if not $file_name;
        return undef if not openhandle($file);
    }
    else {
        die "Unknown argument";
    }

    return $open_files->{$file_name}{'eof'};
}

sub size {
    my ($file) = @_;
    return undef if not $file;

    my $file_name;

    if ( not ref $file ) {
        return undef unless exists $open_files->{$file};
        return (CORE::stat($file))[7] if ( -r $file );
    }
    elsif ( ref $file eq 'GLOB' ) {
        return undef unless exists $open_handles->{$file};

        $file_name = name($file);
        return undef if not $file_name;

        if ( $open_files->{$file_name}{'pid'} != 0 ) {
            update_size($file);
            return $open_files->{$file_name}{'real_size'};
        }

        return (CORE::stat($file_name))[7] if ( -r $file_name );
    }
    else {
        die "Unknown argument";
    }

    return undef;
}

sub progress {
    my ($file) = @_;
    return undef if not $file;

    my $file_name;

    if ( not ref $file ) {
        return undef unless exists $open_files->{$file};
        $file_name = $file;
    }
    elsif ( ref $file eq 'GLOB' ) {
        return undef unless exists $open_handles->{$file};

        $file_name = name($file);
        return undef if not $file_name;
    }
    else {
        die "Unknown argument";
    }

    my $ref = $open_files->{$file_name};

    update_size($file) if ( $ref->{'pid'} != 0 );

    my $progress = $ref->{'eof'} ? 1
                                 : $ref->{'bytes_read'} / $ref->{'real_size'};

    $open_files->{$file_name}{'progress'} = $progress if ( $progress > $ref->{'progress'} );

    return $ref->{'progress'};
}

sub new_progress {
    my ($file, $threshold) = @_;
    return undef if not $file;

    $threshold ||= 1;

    my $file_name;

    if ( not ref $file ) {
        return undef unless exists $open_files->{$file};
        $file_name = $file;
    }
    elsif ( ref $file eq 'GLOB' ) {
        return undef unless exists $open_handles->{$file};

        $file_name = name($file);
        return undef if not $file_name;
    }
    else {
        die "Unknown argument";
    }

    my $ref = $open_files->{$file_name};
    my $change = (progress($file) - $open_files->{$file_name}{'prev_progress'}) * 100;
    my $new_change = 0;

    if ( $change > $threshold ) {

        $open_files->{$file_name}{'prev_progress'} = progress($file);

        my ( $frac, $whole ) = POSIX::modf($change);
        $open_files->{$file_name}{'progress_frac'} += $frac;
        $new_change = $whole;
        ( $frac, $whole ) = POSIX::modf($open_files->{$file_name}{'progress_frac'});
        $open_files->{$file_name}{'progress_frac'} = $frac;
        $new_change += $whole;
    }

    return $new_change;
}

sub set_progress_state {
    my ($file, $text) = @_;
    return undef if ( not $file or not defined $text );

    my $file_name;

    if ( not ref $file ) {
        return undef unless exists $open_files->{$file};
        $file_name = $file;
    }
    elsif ( ref $file eq 'GLOB' ) {
        return undef unless exists $open_handles->{$file};

        $file_name = name($file);
        return undef if not $file_name;
    }
    else {
        die "Unknown argument";
    }

    $open_files->{$file_name}{'progress_state'} = $text;

    return $text;
}

sub progress_state {
    my ($file) = @_;
    return undef if not $file;

    my $file_name;

    if ( not ref $file ) {
        return undef unless exists $open_files->{$file};
        $file_name = $file;
    }
    elsif ( ref $file eq 'GLOB' ) {
        return undef unless exists $open_handles->{$file};

        $file_name = name($file);
        return undef if not $file_name;
    }
    else {
        die "Unknown argument";
    }

    return $open_files->{$file_name}{'progress_state'};

}

sub read_buffer {
    my ($file, $timeout) = @_;
    return undef if not $file;

    my $file_name = '';
    my $read_fd_map = '';
    my $bytes_read = 0;

    $timeout ||= $read_timeout;

    if ( not ref $file ) {
        return undef if not exists $open_files->{$file};
        $file_name = $file;
        $file = $open_files->{$file}{'handle'};
    }
    elsif ( ref $file eq 'GLOB' ) {
        return undef if not openhandle($file);
        $file_name = name($file);
    }
    else {
        die "Unknown argument"
    }

    $last_incomplete_line->{$file_name} ||= '';
    vec($read_fd_map, fileno($file), 1) = 1;

    return undef unless select($read_fd_map, undef, undef, $timeout) >= 0;
    return undef unless vec($read_fd_map, fileno($file), 1);

    $open_files->{$file_name}{'bytes_read'}
        += $bytes_read
         = sysread($file, $buffer->{$file_name}, $open_files->{$file_name}{'read_buffer_size'});

    if (not $bytes_read) {
        $open_files->{$file_name}{'eof'} = 1;
        return $last_incomplete_line->{$file_name};
    }

    $open_files->{$file_name}{'bytes_read'} += $bytes_read;

    $buffer->{$file_name} = $last_incomplete_line->{$file_name} . $buffer->{$file_name};
    $last_incomplete_line->{$file_name} =
        (substr($buffer->{$file_name}, -1) !~ /[\r\n]/ && $buffer->{$file_name} =~ s|([^$/]*)$||) ? $1 : '';

    return $buffer->{$file_name} ? split(m|$/|, $buffer->{$file_name})
                                 : undef;

    #return (splice @{ $complete_lines->{$file_name} }, 0, 1)[0] if (defined wantarray and not wantarray);

    #return ( $lines_in_buffer <= $num_lines ) ? (splice @{ $complete_lines->{$file_name} }, 0, $lines_in_buffer)
    #                                          : (splice @{ $complete_lines->{$file_name} }, 0, $num_lines)
}

sub read_lines {
    my ($file, $num_lines) = @_;
    $num_lines ||= $lines_per_read;

    my $file_name = '';
    my $bytes_read = 0;
    my @lines;

    require bytes;

    if ( not ref $file ) {
        return undef if not exists $open_files->{$file};
        $file_name = $file;
        $file = $open_files->{$file}{'handle'};
    }
    elsif ( ref $file eq 'GLOB' ) {
        return undef if not openhandle($file);
        $file_name = name($file);
    }
    else {
        die "Unknown argument";
    }

    return 0 if $open_files->{$file_name}{'eof'};

    if ( $open_files->{$file_name}{'selector'}->can_read ) {

        for (1 .. $num_lines) {
            $_ = <$file>;
            last unless defined $_;
            $bytes_read += bytes::length($_);
            chomp;
            push @lines, $_
        }
    }

    $open_files->{$file_name}{'bytes_read'} += $bytes_read;

    $open_files->{$file_name}{'eof'} = 1
        if (scalar @lines < $num_lines);

    return \@lines;
}

sub read_line {
    my ($file) = @_;

    return @{read_lines($file, 1)}[0];
}

sub close {
    my ($file) = @_;
    return undef if not $file;

    if ( not ref $file ) {
        return undef if not exists $open_files->{$file};
        close $open_files->{$file}{'handle'} if ( openhandle($open_files->{$file}{'handle'}) );
        waitpid $open_files->{$file}{'pid'}, 0 if ( $open_files->{$file}{'pid'} > 0 );
        delete $open_files->{$file};
    }
    elsif ( ref $file eq 'GLOB' ) {
        my $file_name = name($file);
        return undef if not $file_name;
        close $file if openhandle($file);
        waitpid $open_files->{$file_name}{'pid'}, 0 if ( $open_files->{$file_name}{'pid'} > 0 );
        delete $open_files->{$file_name};
    }
    else {
        die "Unknown argument";
    }

    update_map();
    return 1;
}

1;
} # end module File::Nonblock
