package SpamReport::Maillog;
use SpamReport::Data;

use common::sense;

use vars qw/$VERSION/;
$VERSION = '2016022601';

use Time::Local;
use File::Basename;
use Regexp::Common qw/ Maillog /;
use Socket qw(inet_aton inet_ntoa);
use Sys::Hostname::Long qw(hostname_long);

my $hostname = hostname_long();
my $main_ip = inet_ntoa(scalar gethostbyname($hostname || 'localhost') || pack("N", '127.0.0.1'));

my @time = CORE::localtime(time);
my $tz_offset = timegm(@time) - timelocal(@time);
my @months = qw[Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec];
my %month_to_ord = map {$months[$_] => $_} (0 .. $#months);

sub find_dovecot_logins {
    my ($lines, $year, $end_time, $in_zone) = @_;
    my @lines = @$lines;
    my %days = %{$data->{'OPTS'}{'dovecot_days'}};
    if ($data->{'OPTS'}{'datelimit'} eq 'not today') {
        delete $days{$data->{'OPTS'}{'dovecot_today'}};
    }
    elsif ($data->{'OPTS'}{'datelimit'} eq 'only today') {
        %days = ($data->{'OPTS'}{'dovecot_today'} => 1);
    }
    
    unless ($in_zone->[0]) {
        if (exists $days{substr($lines[0],0,6)} or
            exists $days{substr($lines[$#lines],0,6)}) {
            $in_zone->[0] = 1
        }
        else {
            return
        }
    }
    for (@lines) {
        unless (exists $days{substr($_,0,6)}) {
            $in_zone->[0] = 0;
            return
        }
        if ( /Login: user=<(?!__cpanel)(\S+?)>/ ) {
            my $login = $1;
            $data->{'logins'}{$login}{'total_logins'}++;
            if ( /rip=(?!127\.0\.0\.1)(?!$main_ip)(\S+?),/ ) {
                $data->{'logins'}{$login}{'logins_from'}{$1}++
            }
        }
    }
}

# implemented: SUSP.LOG1 account suspect if login IPs have >2 unique leading 3 octets
# indicate on >10
sub analyze_logins {
    for my $login (keys %{$data->{'logins'}}) {
        if (defined($data->{'OPTS'}{'user'})) {
            next if $login =~ /[\@+]([^\@+]+)/
                && $data->{'OPTS'}{'user'} ne $data->{'domain2user'}{$1};
            next if $login !~ /[\@+]/;
        }
        my %prefix = map { /^(\d+\.\d+\.)/ or die $_; ($1, 1) } keys %{$data->{'logins'}{$login}{'logins_from'}};
        next unless scalar(keys %prefix) > 2;
        $data->{'logins'}{$login}{'suspect'} = 1;
        $data->{'logins'}{$login}{'indicate'} = 1 if scalar(keys %prefix) > 10;
        for (keys %{$data->{'logins'}{$login}{'logins_from'}}) {
            $data->{'logins'}{$login}{'country'}{SpamReport::GeoIP::lookup($_)}{$_} += $data->{'logins'}{$login}{'logins_from'}{$_};
        }
    }
}

1;
