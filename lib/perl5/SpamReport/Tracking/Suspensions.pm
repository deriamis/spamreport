package SpamReport::Tracking::Suspensions;
use vars qw($VERSION);
use SpamReport::Data;
use Time::Local;
use common::sense;
$VERSION = '2016022601';
my $abusetool_log = '/var/log/abusetool.log';
my $lockdown_log = '/var/log/lockdown.log';
my $abusepath = '/opt/eig_linux/var/suspended/';
my $midnight = timelocal(0, 0, 0, (localtime)[3..8]);
my $cutoff = $midnight - (60 * 24 * 3600);  # 60 days ago

sub load {
    load_abusetool();
    load_lockdown();
    opendir my $d, $abusepath or do { warn "Unable to open $abusepath : $!"; return };
    while ($_ = readdir($d)) {
        open my $f, '<', $abusepath.$_ or next;
        my $ctime = (stat($f))[10];
        chomp(my $ticket = <$f>);
        close $f;
        if ($ticket && $ctime) {
            $data->{'suspensions'}{$_}{"$ticket.http"}{'disable'} = $ctime
        }
    }
    close $d;
}

sub ticket {
    my ($user) = @_;
    grep { defined($data->{'suspensions'}{$user}{$_}{'disable'}) &&
          !defined($data->{'suspensions'}{$user}{$_}{'enable'}) }
        keys %{$data->{'suspensions'}{$_[0]}}
}

sub ticketed_users {
    my @users;
    for my $user (keys %{$data->{'suspensions'}}) {
        for my $susp (keys %{$data->{'suspensions'}{$user}}) {
            if (defined $data->{'suspensions'}{$user}{$susp}{'disable'} &&
                    !defined $data->{'suspensions'}{$user}{$susp}{'enable'}) {
                push @users, $user;
                last
            }
        }
    }
    @users
}

sub tickets { keys %{$data->{'suspensions'}{$_[0]}} }

sub load_abusetool {
    logs_after(sub {
        my ($date, $type, $action, $user, $ticket) = split /:/, shift;
        $data->{'suspensions'}{$user}{"$ticket.$type"}{$action} = $date;
    }, $abusetool_log, $cutoff)
}

sub load_lockdown {
    logs_after(sub {
        my ($date, $type, $action, $ticket) = split /:/, shift;
        $data->{'suspensions'}{'root'}{"$ticket.$type"}{$action} = $date;
    }, $lockdown_log, $cutoff)
}

sub logs_after {
    my ($handler, $log, $time) = @_;
    my @r;
    return unless -f $log;
    open my $f, '<', $log or do { warn "Unable to open $log : $!"; return };
    while (defined($_ = <$f>)) {
        chomp;
        next unless /^(\d+):/ && $1 > $cutoff;
        $handler->($_);
    }
    close $f;
}

1;
} # end module SpamReport::Tracking::Suspensions
