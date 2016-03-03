package SpamReport::Data;
use common::sense;
use Exporter;
use Storable qw(lock_store lock_retrieve retrieve);
use POSIX qw(strftime);

use vars qw($VERSION $data @ISA @EXPORT $MAX_RETAINED $loadcronfail);
use vars qw($logpath $cronpath);
$VERSION = '2016022601';
@ISA = 'Exporter';
@EXPORT = qw($data);
$data = {};
$MAX_RETAINED = 4;
$loadcronfail = '';

$logpath = "/opt/hgmods/logs/spamreport.dat";
$cronpath = "/opt/hgmods/logs/spamreportcron.dat";

sub loadcron {
    my ($path) = @_;
    if (defined $path && -e $path) {
        print "Loading $path\n";
        return retrievecron($path)
    }
    elsif (defined $path || ! -e $cronpath) {
        $loadcronfail = "no such file: @{[defined $path ? $path : $cronpath]}";
        return
    }
    else { $path = $cronpath }
    my ($fresh, $date) = _times($path);
    if ($fresh) {
        print "Loading $path ($date)\n";
        return retrievecron($path)
    }
    else {
        rotatecron();
        $loadcronfail = "file is too old: $path ($date)";
    }
    return;
}

sub _times {
    my ($path) = @_;
    my @time = localtime((stat($path))[9]);
    my $day = POSIX::strftime("%F", @time);
    my $date = POSIX::strftime("%F %T", @time);
    my $fresh = POSIX::strftime("%F", localtime()) eq $day;
    return ($fresh, $date);
}

my %cronkeys = map { ($_, 1) }
    qw( dest_domains ip_addresses logins mail_ids recipient_domains scriptdirs senders scripts
        responsibility domain_responsibility bounce_responsibility owner_responsibility
        bounce_owner_responsibility mailbox_responsibility forwarder_responsibility
        young_users young_mailboxes outip outscript hourly_volume total_outgoing total_bounce
        OPTS
    );
sub savecron {
    my %newdata;
    for (keys %cronkeys) {
        $newdata{$_} = $data->{$_}
    }
    lock_store \%newdata, $cronpath;
    #DumpFile($cronpath, \%newdata);
}

sub exitsavecron {
    for (keys %$data) {
        delete $data->{$_} unless exists $cronkeys{$_}
    }
    #DumpFile($cronpath, $data);
    rotatecron() if -e $cronpath;
    lock_store $data, $cronpath;
    exit
}

sub retrievecron {
    my ($path) = @_;
    $data = lock_retrieve($path);
    #$data = LoadFile($path)
}

sub load {
    my ($path) = @_;
    $path = $logpath unless defined $path;
    my ($fresh, $date) = _times($path);
    print "Loading $path ($date)\n";
    #$data = LoadFile($path);
    $data = lock_retrieve($path);
}

sub save {
    rotate();
    #DumpFile($logpath, $data);
    lock_store $data, $logpath;
}

sub rotate {
    my ($path) = @_;
    $path = $logpath unless defined $path;
    my @logs = sort { -M $a <=> -M $b } glob "$path*";
    unlink for @logs[$MAX_RETAINED..$#logs];
    for (sort { -M $b <=> -M $a } @logs) {
        next unless /.(\d+)$/;
        my ($this, $next) = ($1, $1 + 1);
        rename "$path.$this", "$path.$next";
    }
    rename $path, "$path.1";
}

sub rotatecron { rotate($cronpath) }

sub disable {
    *{"SpamReport::Data::load"}
    = *{"SpamReport::Data::save"}
    = *{"SpamReport::Data::retrievecron"}
    = *{"SpamReport::Data::savecron"} = sub { };
    *{"SpamReport::Data::exitsavecron"} = sub { exit };
}

sub details {
    my ($file) = @_;
    $file =~ m,/([^/]+)$,;
    my %detail = (name => (defined($1) ? $1 : $file));
    my $cache;  eval { $cache = retrieve($file) };
    if ($@) {
        $detail{'status'} = "broken $@";
        return \%detail
    }
    $detail{'type'} = (($file =~ /spamreportcron\.dat/) ? 'cron' : 'cache');
    $detail{'status'} = 'ok';
    $detail{'size'} = -s $file;
    $detail{'emails'} = scalar(keys(%{$cache->{'mail_ids'}}));
    $detail{'outgoing'} = $cache->{'total_outgoing'};
    $detail{'bounces'} = $cache->{'total_bounce'};
    $detail{'OPTS'} = $cache->{'OPTS'};
    return \%detail
}

# --ls displays files like '.3' '.test' '.1(cron)'.  load these (without (cron)).
sub resolve {
    my ($name) = @_;
    $logpath .= $name;
    die "Unresolved cache name: $name" unless -f $logpath;
}
sub resolvecron {
    my ($name) = @_;
    $cronpath .= $name;
    die "Unresolved croncache name: $name" unless -f $cronpath;
}

1;
