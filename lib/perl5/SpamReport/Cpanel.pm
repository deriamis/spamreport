package SpamReport::Cpanel;

use strict;
use warnings;

use vars qw/$VERSION/;
$VERSION = '2016022601';

use Time::Local;
use Regexp::Common qw( SpamReport );
use File::Nonblock;
use SpamReport::Data;

sub young_users {
    my $time = time();
    for my $user (keys %{$data->{'user2domain'}}) {
        next if $user eq 'nobody';
        open my $f, '<', "/var/cpanel/users/$user"
            or do { warn "Unable to open /var/cpanel/users/$user : $!"; next };
        while ($_ = <$f>) {
            if (/^STARTDATE=(\d+)/ && ($time - $1) < (14 * 3600*24)) {
                $data->{'young_users'}{$user}++;
                last
            }
        }
        close $f;
    }
}

sub map_userdomains {
    my ($userdomains_path) = @_;

    my %user2domain = ();
    my %domain2user = ();

    open my $fh, '<', $userdomains_path or die "Unable to open $userdomains_path : $!";
    %domain2user = map {
        chomp;
        my ($domain, $user) = split ': ';
        push @{ $user2domain{$user} }, $domain;
        $domain => $user;
    } grep { !m/^(?:#|$)/ } <$fh>;
    close $fh;

    return (\%user2domain, \%domain2user);
}

sub map_userowners {
    my ($trueuserowners_path) = @_;

    my %user2owner = ();
    my %owner2user = ();

    open my $fh, '<', $trueuserowners_path or die "Unable to open $trueuserowners_path : $!";
    %user2owner = map {
        chomp;
        my ($user, $owner) = split ': ';
        push @{ $owner2user{$owner} }, $user;
        $user => $owner;
    } grep { !m/^(?:#|$)/ } <$fh>;
    close $fh;

    return (\%user2owner, \%owner2user);
}

sub map_valiases {
    my ($valiases_path) = @_;

    my %alias2dest = ();
    my %dest2alias = ();

    my %temp;

    opendir my $vd, $valiases_path or die "Unable to open $valiases_path : $!";
    for my $valias_file ( map { $valiases_path . '/' . $_ } readdir($vd) ) {
        if ( -s $valias_file > 28 ) {

            open my $fh, '<', $valias_file;
            %temp = map {
                chomp;
                my @line = split ': ';
                # infiniti had some malformed .bak'd files
                if (defined $line[1]) {
                    my @destinations = grep { m/^[^|:|"]/ } split /,\s*/, $line[1];
                    $line[0] => \@destinations;
                } else { () }
            } grep { !m/^(\#|\*|\s*$)/ } <$fh>;
            close $fh;

        }

        @alias2dest{keys %temp} = values %temp;
        undef %temp;
    }
    closedir $vd;

    for my $alias (keys %alias2dest) {
        for my $dest ( @{ $alias2dest{$alias} } ) {
            push @{ $dest2alias{$dest} }, $alias;
        }
    }

    return (\%alias2dest, \%dest2alias);
}

# yes this is necessary :p  http://hgfix.net/paste/view/0766d18b
our ($safety, $alias_domain, %bad_valiases);
sub find_offserver {
    my (@aliases) = @_;
    local ($safety) = ($safety + 1);
    my @results;
    if ($safety > 10) {
        warn "[NOTICE] circular definitions found in /etc/valiases/$alias_domain\n"
            unless $bad_valiases{$alias_domain}++;
        return ()
    }
    for (@aliases) {
        if (exists $data->{'alias2dest'}{$_}) {
            push @results, find_offserver(@{$data->{'alias2dest'}{$_}});
        }
        elsif (/[\@+]([^\@+]+)$/ && !exists($data->{'domain2user'}{$1})) {
            push @results, $_
        }
    }
    return @results
}
sub offserver_forwarders {
    for my $alias (keys %{$data->{'alias2dest'}}) {
        $alias_domain = '(UNKNOWN)';  $alias_domain = $1 if $alias =~ /[\@+]([^\@+]+)$/;
        next if defined($data->{'OPTS'}{'user'}) &&
            $data->{'domain2user'}{$alias_domain} ne $data->{'OPTS'}{'user'};
        $safety = 0;
        for (find_offserver(@{$data->{'alias2dest'}{$alias}})) {
            $data->{'offserver_forwarders'}{$alias}{$_}++;
        }
    }
}

my $cpaddpop = qr/$RE{'cpanel'}{'addpop'}/;
my $aptimest = qr/$RE{'apache'}{'timestamp'}/;
sub find_email_creation {
    my ($lines, $end_time, @search_list) = @_;
    for my $line ( @{ $lines } ) {
            
        if ( $line =~ $cpaddpop ) {

            my %vars = map { split /=/ } split /&/, $4;
            my $login = $vars{'email'} . '@' . $vars{'domain'};

            next if ( scalar @search_list and not grep { $_ eq $login } @search_list );

            my $ipaddr = $1;
            my $username = $2;
            my $timestamp = 0;

            if ( $3 =~ $aptimest ) {
                $timestamp = timegm($6, $5, $4, $2, $1 - 1, $3 - 1900) - ($7 * 36);
            }

            last if ( $timestamp > $end_time );

            $data->{'logins'}{$login}{'created_from'} = $ipaddr;
            $data->{'logins'}{$login}{'created_by'} = $username;
            $data->{'logins'}{$login}{'created_on'} = $timestamp;
        }

    }

    1;
}

sub next {
    my ($file_handle, $OPTS, $progress_func) = @_;

    my $last_timestamp = '';
    my $file_pos = File::Nonblock::tell($file_handle);
    my $fast_forward = 0;
    my $num_lines ||= $OPTS->{'read_lines'} || 100;

    while ( not File::Nonblock::eof($file_handle) ) {

        my $lines;
        my $log_timestamp;

        if ( $file_pos == 0 ) {
            $lines = File::Nonblock::read_lines($file_handle, 1);
            $num_lines--;
        }
        else {
            $lines = File::Nonblock::read_lines($file_handle, $num_lines);
        }

        for ( my $n = 0; $n < scalar @{ $lines }; $n++ ) {

            if ( $lines->[$n] =~ $cpaddpop ) {

                if ( $3 ne $last_timestamp and $3 =~ $cpaddpop ) {
                    $log_timestamp = timegm($6, $5, $4, $2, $1 - 1, $3 - 1900) - ($7 * 36);

                    next if ( $log_timestamp < $OPTS->{'start_time'} );
                    return [ splice @{ $lines }, 0, $n ] if ( $log_timestamp > $OPTS->{'end_time'} );
                    return [ splice @{ $lines }, $n, scalar @{ $lines } - $n ];
                }
            }
        }
    }
}

1; # end module SpamReport::Cpanel
