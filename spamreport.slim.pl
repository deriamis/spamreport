#!/usr/bin/perl

BEGIN {
package SpamReport::GeoIP;
use Geo::IPfree;
use IP::Country::Fast;
use FindBin qw( $Bin );
use vars qw($VERSION);
$VERSION = '2016022601';

my ($geo, $ipc);

sub init {
    $geo = Geo::IPfree->new("$Bin/ipscountry.dat");
    $geo->Faster;
    $ipc = IP::Country::Fast->new;
}

sub lookup {
    my ($ip) = @_;
    return $ipc->inet_atocc($ip) || ($geo->LookUp($ip))[0]
}

1;
} # end module SpamReport::GeoIP
BEGIN {
$INC{'SpamReport/GeoIP.pm'} = '/dev/null';
}

BEGIN {
package SpamReport::Data;
use Exporter;
use Storable qw(fd_retrieve store_fd);
use POSIX qw(strftime);
use Fcntl qw(:flock);
use File::Which qw ( which );
use File::Temp;
use common::sense;

use vars qw($VERSION $data @ISA @EXPORT $MAX_RETAINED $loadcronfail);
use vars qw($logpath $cronpath);
$VERSION = '2016022601';
@ISA = 'Exporter';
@EXPORT = qw($data);
my $gzip = which('gzip');

$logpath = "/opt/hgmods/logs/spamreport.dat.gz";
$cronpath = "/opt/hgmods/logs/spamreportcron.dat.gz";

$data = {};
$MAX_RETAINED = 4;
$loadcronfail = '';

sub retrieve {
    my ($path, $lock) = @_;
    if ($path =~ /\.gz(?:$|\.)/) {
        open my $fd, '-|', $gzip, '-dc', $path
            or die "Couldn't fork $gzip for $path : $!";
        if ($lock) { flock $fd, LOCK_SH or die "Couldn't lock $path : $!"; }
        my $ref = fd_retrieve($fd)
            or die "Unable to read $path : $!";
        close $fd;
        return $ref
    }
    elsif ($lock) {
        return Storable::lock_retrieve($path)
    }
    else {
        return Storable::retrieve($path)
    }
}
sub lock_retrieve { retrieve(shift, 1) }

sub lock_store {
    my ($ref, $path) = @_;
    if ($path =~ /\.gz$/) {
        $path =~ m,^(.*)/[^/]+$, or die "Couldn't find directory component of $path";
        my $tmp = File::Temp::mktemp($1."/srgzipout-XXXXXX");

        open my $fd, '|-', "$gzip > $tmp"
            or die "Couldn't fork $gzip for $path : $!";
        store_fd $ref, $fd or die "Failed to store to $path : $!";
        close $fd;
        rename $tmp, $path or die "Unable to rename $tmp to $path : $!";
    } else {
        return Storable::lock_store($ref, $path)
    }
}

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
    if (-e $path) {
        my ($fresh, $date) = _times($path);
        if ($fresh) {
            print "Loading $path ($date)\n";
            return retrievecron($path)
        }
        else {
            rotatecron();
            $loadcronfail = "file is too old: $path ($date)";
        }
    }
    else {
        $loadcronfail = "no such fail: $path";
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
    print "Saving cron $cronpath\n";
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
    return unless $fresh;
    print "Loading $path ($date)\n";
    #$data = LoadFile($path);
    $data = lock_retrieve($path);
}

sub save {
    rotate();
    print "Saving cache $logpath\n";
    #DumpFile($logpath, $data);
    lock_store $data, $logpath;
}

sub rotate {
    my ($path) = @_;
    $path = $logpath unless defined $path;
    my @logs = sort { -M $a <=> -M $b } glob "$path*";
    unlink for @logs[$MAX_RETAINED..$#logs];
    for (sort { -M $b <=> -M $a } @logs) {
        next unless /.(\d+)\.gz$/;
        my ($this, $next) = ($1, $1 + 1);
        rename "$path.$this.gz", "$path.$next.gz";
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
    return $name if $name =~ m(^/);
    $logpath .= $name;
    die "Unresolved cache name: $name" unless -f $logpath;
}
sub resolvecron {
    my ($name) = @_;
    return $name if $name =~ m(^/);
    $cronpath .= $name;
    die "Unresolved croncache name: $name" unless -f $cronpath;
}

1;
} # end module SpamReport::Data
BEGIN {
$INC{'SpamReport/Data.pm'} = '/dev/null';
}

BEGIN {
package SpamReport::Tracking::Scripts;
use YAML::Syck qw(DumpFile LoadFile);
use vars qw($VERSION);
use File::Which qw ( which );
use Time::Local;
use SpamReport::GeoIP;
use common::sense;

$VERSION = '2016022401';
my $md5sum = which('md5sum');
my $trackpath = "/opt/hgmods/logs/spamscripts.dat";
my $midnight = timelocal(0, 0, 0, (localtime)[3..8]);

my $tracking;

sub load { eval { $tracking = LoadFile($trackpath) } }
sub save { if ($tracking) { prune(); DumpFile($trackpath, $tracking) } }

my %cache;

# script tracking is relatively expensive and probably
# shouldn't happen except on --cron runs
sub disable {
    *{"SpamReport::Tracking::Scripts::load"}
    = *{"SpamReport::Tracking::Scripts::save"}
    = *{"SpamReport::Tracking::Scripts::script"} = sub { }
}

my $time = time();
sub script {
    my ($path, $ip) = @_;
    my $md5 = md5sum($path) || return;
    if ($md5 =~ /^[a-f0-9]{32}$/i) {
        $tracking->{$md5}{$midnight}{'ips'}{$ip}++;
        $tracking->{$md5}{$midnight}{'paths'}{$path}++;
    }
}

sub md5sum {
    my ($path) = @_;
    return $cache{$path} if exists $cache{$path};
    return unless -f $path;
    open my $f, '-|', $md5sum, $path or return;
    my $md5 = <$f>;
    close $f;
    $md5 =~ s/ .*//;
    chomp $md5;
    $md5
}

sub prune {
    my $cutoff = $midnight - (180 * 3600 * 24);  # 180 days ago
    for my $md5 (keys %$tracking) {
        for (keys %{$tracking->{$md5}}) {
            if ($_ < $cutoff) {
                delete $tracking->{$md5}{$_}
            }
        }
    }
}

sub latest {
    my %r;
    for my $md5sum (keys %$tracking) {
        my $latest = (sort { $b <=> $a } keys %{$tracking->{$md5sum}})[0];
        my $ips = scalar(keys %{$tracking->{$md5sum}{$latest}{'ips'}});
        my %ip16; for (keys %{$tracking->{$md5sum}{$latest}{'ips'}}) { $ip16{$1}++ if /^(\d+\.\d+\.)/ }
        my %geo; for (keys %{$tracking->{$md5sum}{$latest}{'ips'}}) { $geo{SpamReport::GeoIP::lookup($_)}++ }
        my (%files, %paths);
        my $count = 0; for (values %{$tracking->{$md5sum}{$latest}{'ips'}}) { $count += $_ }
        for my $time (keys %{$tracking->{$md5sum}}) {
            for (keys %{$tracking->{$md5sum}{$time}{'paths'}}) {
                $paths{$_} += $tracking->{$md5sum}{$time}{'paths'};
                next unless m,/([^/]+)$,;
                $files{$1} += $tracking->{$md5sum}{$time}{'paths'}
            }
        }
        $r{$md5sum} = {
            latest => $latest,
            count => $count,
            ips => $ips,
            ip16 => scalar(keys %ip16),
            geo => \%geo,
            file => (sort { $files{$b} <=> $files{$a} } keys %files)[0],
            path_variations => scalar(keys %paths),
            file_variations => scalar(keys %files),
        }
    }
    \%r
}

sub paths {
    my ($md5) = @_;
    my %r;
    for my $time (keys %{$tracking->{$md5}}) {
        for (keys %{$tracking->{$md5}{$time}{'paths'}}) {
            $r{$_}{'count'} += $tracking->{$md5}{$time}{'paths'}{$_};
            $r{$_}{'latest'} = $time if $time > $r{$_}{'latest'};
        }
    }
    \%r
}

sub get_md5 { return $tracking->{$_[0]} }

# /usr/bin/time perl -MDigest::MD5 -le '$m = Digest::MD5->new; open my $f, "<", "bigfile"; $m->addfile($f); print $m->hexdigest'
# cd573cfaace07e7949bc0c46028904ff
# 3.86user 0.47system 0:04.34elapsed 99%CPU (0avgtext+0avgdata 2432maxresident)k
# 0inputs+0outputs (0major+674minor)pagefaults 0swaps
#
# # /usr/bin/time md5sum bigfile 
# cd573cfaace07e7949bc0c46028904ff  bigfile
# 2.75user 0.41system 0:03.19elapsed 98%CPU (0avgtext+0avgdata 692maxresident)k
# 0inputs+0outputs (0major+216minor)pagefaults 0swaps
#
# --
# 1GB file.  md5sum: a bit faster, 700MB of RAM.
# vs. Digest::MD5: a bit slower, 2500MB of RAM.

1;
} # end module SpamReport::Tracking::Scripts
BEGIN {
$INC{'SpamReport/Tracking/Scripts.pm'} = '/dev/null';
}

BEGIN {
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
    opendir my $d, $abusepath or return;
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
BEGIN {
$INC{'SpamReport/Tracking/Suspensions.pm'} = '/dev/null';
}

BEGIN {
package SpamReport::Tracking::Performance;
use SpamReport::Data;
use vars qw($VERSION);
use common::sense;

$VERSION = '2016022401';
my $trackpath = "/opt/hgmods/logs/spamperformance.log";

# 1MB is enough logs for anybody
if (-s($trackpath) > 1024*1024) {
    my @lines;
    if (open my $f, '<', $trackpath) {
        while ($_ = <$f>) {
            last if @lines > 100;
            push @lines, $_
        }
        close $f;
    }
    if (@lines && open my $f, '>', $trackpath) {
        print {$f} @lines;
        close $f;
    }
}

my $start = time();
my $ARGS = "@ARGV";

END {
    my $end = time();
    if (open my $f, '>>', $trackpath) {
        printf {$f} "%s + %d secs : %d tracked emails : %s\n", 
            scalar(localtime($start)),
            $end - $start, 
            scalar(keys %{$data->{'mail_ids'}}),
            $ARGS;
        close $f;
    }
}

1;
} # end module SpamReport::Tracking::Performance
BEGIN {
$INC{'SpamReport/Tracking/Performance.pm'} = '/dev/null';
}

BEGIN {
package Regexp::Common::Exim;

use strict;
use warnings;

use Regexp::Common qw(pattern clean no_defaults);

use vars qw/$VERSION/;
$VERSION = '2015122201';

pattern name => [ qw(exim message) ],
      create => q/^((?:\S+) (?:\S+)) (?:(\S+) (<=|=>|->|>>|\*>|\*\*|==|Completed|SMTP connection outbound)(?:$| ))(.*)/;

pattern name => [ qw(exim exec) ],
      create => q/((\S+) (\d+) args: (.*))/;

pattern name => [ qw(exim inbound) ],
      create => q/((\S+\s*(<[^>]+>)?) (.*))/;

pattern name => [ qw(exim inbound local) ],
      create => q/(^(\S+\s*(<[^>]+>)?) ((?:(?:R=\S+) )?(?:U=\S+) (?:P=local) (?:S=\d+)(?: (?:id=\S+))?(?: (?:T=".*"))?))/;

pattern name => [ qw(exim inbound remote) ],
      create => q/(^(\S+\s*(<[^>]+>)?) ((?:H=.*? \[[^\]]+\]:\d+) (?:I=\[[^\]]+\]:\d+) (?:P=\S+)(?: (?:X=\S+)(?: (?:DN=".*?"))?)?(?: (?:A=dovecot_[^:]+:\S+))?(?: (?:S=\d+))?(?: (?:id=\S+))?(?: (?:T=".*"))?))/;

pattern name => [ qw(exim outbound) ],
      create => q/((\d+) (\S+) (\S+) (<?[^>\s]+>?) ((?:I=\S+) (?:S=\S+) (?:F=.*)))/;

pattern name => [ qw(exim delivery) ],
      create => q/(^(.*?\s*(?:\([^\)]+?\)?)?(?: <[^>]+>)?) ((?:F=\S+) (?:R=\S+) (?:T=\S+)(?: (?:S=\d+)(?: (?:H=.*? \[([^\]]+)\])(?: (?:X=\S+)(?: (?:DN=".*"))?)?)?(?: (?:C=".*"))?)?))/;

pattern name => [ qw(exim delivery failure) ],
      create => q/(^(\S+\s*(<[^>]+>)?) (.*?): (.*))/;

pattern name => [ qw(exim delivery pipe) ],
      create => q/(^\|(.*?) \(([^\)]+?)\) <([^>]+)>)/;

pattern name => [ qw(exim info address) ],
      create => q/(^([^@+]+[@+]\S+)(?: <([^>]+)>)?)/;

pattern name => [ qw(exim info host) ],
      create => q/(^(\S*\s*\([\)]+\)) (\[[^\]]+\]:\d+))/;

pattern name => [ qw(exim info timestamp) ],
      create => q/(^(\d{4})-(\d{2})-(\d{2})\s(\d{2}):(\d{2}):(\d{2}))/;

pattern name => [ qw(exim info HELO) ],
      create => q/(^(\S+)?\s*\(([^\)]+)\))/;

pattern name => [ qw(exim info network) ],
      create => q/(^\[([^:]+)\]:(\d+)$)/;

pattern name => [ qw(exim info login) ],
      create => q/(A=dovecot_([^:]+):(\S+))/;

pattern name => [ qw(exim fields) ],
      create => q/((\w+=(?:".*"|\S+))\s*)/;

pattern name => [ qw(exim info fields) ],
      create => q/((\w+)=(?:"(.*)"|(\S+))\s*)/;

pattern name => [ qw(exim info cron) ],
      create => q,^\S+ \S+ cwd=\S+ 9 args: /usr/sbin/sendmail -FCronDaemon -i -odi -oem -oi -t -f (\S+)$,;

pattern name => [ qw(exim info script) ],
      create => q,^\S+ \S+ cwd=(/home\S+)(?!.*-FCronDaemon.*$),;

1;

} # end module Regexp::Common::Exim
BEGIN {
$INC{'Regexp/Common/Exim.pm'} = '/dev/null';
}

BEGIN {
package Regexp::Common::Maillog;

use strict;
use warnings;

use Regexp::Common qw(pattern clean no_defaults);

use vars qw/$VERSION/;
$VERSION = '2015122201';

pattern name => [ qw(mail login) ],
      create => q/^((?:\w{3})\s{1,2}(?:\d{1,2})\s(?:\d{2}):(?:\d{2}):(?:\d{2})) \S+ \S+ ([^-]+)-login: Login: (.*)/;

pattern name => [ qw(mail login timestamp) ],
      create => q/^(\w{3})\s{1,2}(\d{1,2})\s(\d{2}):(\d{2}):(\d{2})$/;

pattern name => [ qw(mail login info) ],
      create => q/^user=<([^>]+)>.*?rip=([^,]+), lip=([^,]+),.*/;

1;
} # end module Regexp::Common::Maillog
BEGIN {
$INC{'Regexp/Common/Maillog.pm'} = '/dev/null';
}

BEGIN {
package Regexp::Common::SpamReport;

use strict;
use warnings;

use Regexp::Common qw(pattern clean no_defaults);

use vars qw/$VERSION/;
$VERSION = '2015122201';

pattern name => [ qw(spam common_scraped) ],
    create => q/((?:spam|abuse|nobody|void|noreply|info|_)@.*|.*(?:mai\.com|\.gov|\.mil))/;

pattern name => [ qw(spam hi_destination) ],
    create => q/\.?(aol|aim|amazon(?:aws)?|att(?:global|ymail)?|comcast|compuserve|cox(?:inet)?|earthlink|g(?:oogle)?mail|hostmail|(?:windows)?live|mindspring|msn|outlook|prodigy|qwest|rocketmail|rr|swbell|terra|twc|y(?:ahoo(?:fs)?|mail)|verizon(?:mail)?|virgin(?:broadband)?)/;

pattern name => [ qw(spam hi_source) ],
    create => q/\.?(altavista|angelfire|aol|aim|amazon(?:aws)?|att(?:global|ymail)?|bigpond|charter|chooseyourmail|cia|comcast|compuserve|cox(?:inet)?|earthlink|email(?:2me|4u|account|engine|user|x)|excite|email|facebook|falseaddress|fast(?:-?e?mail(?:er)?(?:box)?|imap|messaging)|fbi|fmail|free(?:mail|net)|geocities|ghostmail|gmx|g(?:oogle)?mail|hotmail|hush(?:mail)?|icq(?:mail)?|juno|(?:windows)?live|lycos|msn|mindspring|outlook|prodigy|qwest|rocketmail|swbell|terra|twc|rr|usa|vahoo|verizon(?:mail)?|virgin(?:broadband)?|vnn|y(?:ahoo(?:fs)?|mail)|yandex|zmail)\.(?:com?(?:\.[^.]+)?|[^.]+)/;

pattern name => [ qw(spam spammy_tld) ],
    create => q/\.(cn|hu|br|co\.za|sg|hk|ph|jp|ru|tk|ar|de|gr|vn|kr|cc|co|pw|eu|mx|no|my|se|tw|us|zip|review|country|kim|cricket|science|space|work|party|gq|link|xyz|top|click|win|biz|bid|download|trade|webcam|date|review|faith|racing)(\.|$)/;

pattern name => [ qw(cpanel addpop) ],
    create => q/^(\S+)\s(?:\S+)\s(\S+)\s\[([^\]]+)\]\s"GET\s\/.*?\?(.*?&?cpanel_jsonapi_func=addpop&?.*?)\sHTTP\/1\.\d"/;

pattern name => [ qw(apache timestamp) ],
    create => q/(\d{2})\/(\d{2})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s(-?\d{4})/;

1;
} # end module Regexp::Common::SpamReport
BEGIN {
$INC{'Regexp/Common/SpamReport.pm'} = '/dev/null';
}

BEGIN {
package SpamReport::ANSIColor;
use common::sense;
use Exporter;

use vars qw($VERSION @ISA @EXPORT);
$VERSION = '2016022601';
@ISA = 'Exporter';
@EXPORT = qw($RED $GREEN $YELLOW $MAGENTA $CYAN $NULL);

our ($RED, $GREEN, $YELLOW, $MAGENTA, $CYAN, $NULL) =
    map { "\e[${_}m" } (31, 32, 33, "35;1", 36, 0);

sub suppress {
    $RED = $GREEN = $YELLOW = $MAGENTA = $CYAN = $NULL = ''
}

1;
} # end module SpamReport::ANSIColor
BEGIN {
$INC{'SpamReport/ANSIColor.pm'} = '/dev/null';
}

BEGIN {
package SpamReport::Annotate;
use SpamReport::Data;
use SpamReport::Tracking::Suspensions;
use SpamReport::Output;
use common::sense;

use vars qw/$VERSION %embargo/;
$VERSION = '2016022601';

use SpamReport::ANSIColor;

sub script {
    my ($script) = @_;
    return $script if -d $script;
    if (-f $script && ((stat($script))[2])&0777) {
        $YELLOW . $script . $NULL
    }
    elsif (-f $script) {
        "$RED$script (DISABLED)$NULL"
    }
    else {
        "$RED$script (GONE)$NULL"
    }
}

sub owner {
    my ($user, $ownerkey, $resoldkey) = @_;
    my $u = $user;
    my %resolds = map { ($_, $data->{$resoldkey}{$_}) } @{$data->{'owner2user'}{$u}};
    for (grep { defined $_ && $resolds{$_} } (sort { $resolds{$b} <=> $resolds{$a} } keys %resolds)[0..2]) {
        $user .= sprintf(" $CYAN%s$NULL:%.1f%%", $_, 100*$resolds{$_}/$data->{$ownerkey}{$u})
    }
    $user
}

sub user {
    my ($user) = @_;
    my $u = $user;
    for (SpamReport::Tracking::Suspensions::ticket($u)) {
        $user = "$RED$user $_$NULL"
    }
    if (exists $data->{'in_history'}{$u}) {
        my $delta = (time() - $data->{'in_history'}{$u}) / (24 * 3600);
        if ($delta > 1) {
            $user = sprintf "$MAGENTA%s $MAGENTA(seen: %.1f days)$NULL", $user, $delta
        } else {
            $user = sprintf "$MAGENTA%s $MAGENTA(seen: %.1f hours)$NULL", $user,
                (time() - $data->{'in_history'}{$u}) / 3600
        }
    }
    if (exists $data->{'young_users'}{$u}) {
        $user = "$YELLOW$user $YELLOW(user age)$NULL";
    }
    if (exists $data->{'indicators'}{$u}) {
        $user = "$user $CYAN@{[join ' ', sort keys %{$data->{'indicators'}{$u}}]}$NULL";
    }
    my $todays_mails;
    my %todays_hours; for my $time (time()) {
        for (map { $time-3600*$_ } 0..23) {
            $todays_hours{POSIX::strftime("%F %H", localtime($_))}++
        }
    }
    for (grep { exists $todays_hours{$_} } keys %{$data->{'hourly_volume'}{$u}}) {
        $todays_mails += $data->{'hourly_volume'}{$u}{$_}
    }
    # assumes default 3-4 day window
    if ($data->{'responsibility'}{$u}) {
        my $recency = $todays_mails / $data->{'responsibility'}{$u};
        if ($recency < 0.1) {
            $user = sprintf("$RED%s $RED(stale: %.1f%%)$NULL", $user, $recency*100)
        }
        elsif ($recency > 0.8) {
            $user = sprintf("$YELLOW%s $YELLOW(recent: %.1f%% = @{[SpamReport::Output::commify($todays_mails)]})$NULL", $user, $recency*100)
        }
    }
    #if (exists $data->{'special_indicators'}{$u}{'hi_malware'}) {
    #    my @urls = sample_urls($u);
    #    if (@urls) {
    #        $user .= join '', map { "\n\t$_"} @urls
    #    }
    #}
    $user
}

%embargo = qw(
    IR IRAN
    KP NKOREA
    SD SUDAN
    SY SYRIA
);
sub country {
    my ($code) = @_;
    if (exists $embargo{$code}) {
        "$RED$embargo{$code}$NULL"
    }
    else {
        "$CYAN$code$NULL"
    }
}

sub sample_urls {
    my ($user) = @_;
    my %urls;
    for (keys %{$data->{'mail_ids'}}) {
        next unless exists $_->{'mail_ids'}{'in_queue'};
        open my $f, '-|', "exim -Mvb $_" or next;
        my $b = 0;
        for (<$f>) {
            $urls{$1}++ if m,(http://[\x21-\x7f]+),;
            $b += length($_); last if $b > 1024;
        }
        close $f;
    }
    (grep { defined $_ } List::Util::shuffle(keys %urls))[0..3];
}

1;
} # end module SpamReport::Annotate
BEGIN {
$INC{'SpamReport/Annotate.pm'} = '/dev/null';
}

BEGIN {
package SpamReport::Output;

use SpamReport::Data;
use SpamReport::Annotate;
use SpamReport::GeoIP;
use SpamReport::Tracking::Scripts;
use SpamReport::Tracking::Suspensions;
use SpamReport::Exim;
use SpamReport::Maillog;
use common::sense;

use vars qw/$VERSION/;
$VERSION = '2016022601';

use Time::Local;
use List::Util qw(shuffle sum);
use SpamReport::ANSIColor;
use Regexp::Common qw(SpamReport);

my @time = CORE::localtime(time);
my $tz_offset = timegm(@time) - timelocal(@time);

use Sys::Hostname::Long qw(hostname_long);
my $hostname = hostname_long();

sub head_info {
    my ($OPTS) = @_;
    my $search_delta = $OPTS->{'end_time'} - $OPTS->{'start_time'};
    my $hours = $search_delta / 3600;

    my $start_time = localtime($OPTS->{'start_time'});
    my $end_time = localtime($OPTS->{'end_time'});
    my $sections = join " ", @{ $OPTS->{'run_sections'} };

    print <<END_INFO

SpamReport - Report suspicious mail activity
Written By: Ryan Egesdahl and Julian Fondren

Operation: $OPTS->{'op'}
Load: @{[$OPTS->{'load'} || '(nothing)']}
Want: @{[join " ", sort map { /_(.*)/; $1 } grep { /^want_/ && $OPTS->{$_} } keys %$OPTS]}
@{[$OPTS->{'op'} ne 'report' ? '' :
    ("Report: " . ($OPTS->{'report'} ne 'summary' ? $OPTS->{'report'} :
    ("summary (" . join(" ", sort map { /_(.*)/; $1 } grep { /^with_/ && $OPTS->{$_} } keys %$OPTS) . ")"))
    . "\n")]}
@{[$OPTS->{'load'} eq 'no' ? '' : "Searching $hours hours from [$start_time] to [$end_time] ...\n"]}
END_INFO
}

# width $x => $y;   # same as:  for (length($x)) { $y = $x if $y < $x }
# setmax $x => $y;  # same as:  for ($x) { $y = $x if $y < $x }
# 
# these replaced code such as:
#   $widths[5] = length(keys(%{$latest->{$_}{'file_variations'}})) if length(keys(%{$latest->{$_}{'file_variations'}})) > $widths[4];
# (which has a bug)
sub width ($\$) { ${$_[1]} = length($_[0]) if ${$_[1]} < length($_[0]) }
sub setmax ($\$) { ${$_[1]} = $_[0] if ${$_[1]} < $_[0] }

sub email_search_results {
    my (@emails) = @_;

    if ( exists $data->{'logins'} and scalar keys %{ $data->{'logins'} } > 0 ) {
        if ( scalar @emails > 1 ) {
            map {
                print "    Login:        $_\n";
                print '    Created on:   ' . localtime($data->{'logins'}{$_}{'created_on'}) . "\n";
                print '    Created by:   ' . $data->{'logins'}{$_}{'created_by'} . "\n";
                print '    Created from: ' . $data->{'logins'}{$_}{'created_from'} . "\n\n";
            } keys %{ $data->{'logins'} };
        }
        else {
            if ( not exists $data->{'logins'}{$emails[0]} ) {
                print "\nNot found.\n";
                return
            }

            map {
                print "    Login:        $_\n";
                print '    Created on:   ' . localtime($data->{'logins'}{$_}{'created_on'}) . "\n";
                print '    Created by:   ' . $data->{'logins'}{$_}{'created_by'} . "\n";
                print '    Created from: ' . $data->{'logins'}{$_}{'created_from'} . "\n\n";
            } $emails[0];
        }
    }
    else {
        print "\nNot found.\n";
    }
}

sub analyze_results {
    SpamReport::Exim::analyze_queued_mail_data();
    #SpamReport::Exim::analyze_num_recipients();
    analyze_mailboxes();
    SpamReport::Maillog::analyze_logins();
    analyze_user_indicators();
    analyze_auth_mismatch();

    1;
}

sub print_results {
    print_queue_results() if exists $data->{'queue_top'};
    #print_recipient_results() if exists $data->{'suspects'}{'num_recipients'};
    print_script_results();
    print_responsibility_results() if $data->{'responsibility'};
    print_auth_mismatch() if $data->{'auth_mismatch'};
    note_forwarder_abuse();

    print "\n";
    1;
}

sub cache_ls {
    my @details;
    push @details, SpamReport::Data::details($_)
        for <$SpamReport::Data::cronpath*>,
            <$SpamReport::Data::logpath*>;
    my @legend = qw(NAME SIZE EMAILS OUTGOING START HOURS);
    my @widths = map { length($_) } @legend;
    for (@details) {
        $_->{'name'} =~ s/\.gz(?=\.|$)//;
        $_->{'name'} =~ s/spamreport(cron)?\.dat//;
        $_->{'name'} .= "(cron)" if defined $1;
        width $_->{'name'} => $widths[6];
        width sprintf("%dM", $_->{'size'}/1024/1024) => $widths[0];
        width $_->{'emails'} => $widths[1];
        width $_->{'outgoing'} => $widths[2];
        #width $_->{'bounces'} => $widths[3];
        width ago($_->{'OPTS'}{'start_time'}, 1) => $widths[4];
        width $_->{'OPTS'}{'search_hours'} => $widths[5];
    }
    printf "%$widths[6]s %$widths[0]s %$widths[1]s %$widths[2]s %$widths[4]s %$widths[5]s\n",
        @legend;
    for (sort { $a->{'OPTS'}{'start_time'} <=> $b->{'OPTS'}{'start_time'} } @details) {
        my $line = sprintf "%$widths[6]s %$widths[0]dM %$widths[1]d %$widths[2]d %$widths[4]s %$widths[5]d :: %s -> %s\n",
            $_->{'name'} || 'cache',
            $_->{'size'}/1024/1024,
            $_->{'emails'},
            $_->{'outgoing'},
            #$_->{'bounces'},
            $_->{'OPTS'}{'start_time'} ? ago($_->{'OPTS'}{'start_time'}, 1) : '',
            $_->{'OPTS'}{'search_hours'},
            $_->{'OPTS'}{'start_time'} ? scalar(localtime($_->{'OPTS'}{'start_time'})) : '(unknown)',
            $_->{'OPTS'}{'end_time'} ? scalar(localtime($_->{'OPTS'}{'end_time'})) : '...';
        $line =~ s/(\(cron\))/$GREEN$1$NULL/g;
        print $line
    }
}

sub print_forwarder_abuse {
    my @abuse = sort { $b->[1] <=> $a->[1] } 
                map { [$_, List::Util::sum(values %{$data->{'forwarder_responsibility'}{$_}})] }
                keys %{$data->{'forwarder_responsibility'}};
    my $total = 0; $total += $_->[1] for @abuse;
    unless ($total) { print "No forward abusers found.\n"; return }

    my $omitted = @abuse;
    @abuse = grep { $_->[1]/$total > 0.01 } @abuse unless $data->{'OPTS'}{'full'};
    $omitted -= @abuse;

    my @width = (0, 0);
    for (@abuse) {
        width $_->[1] => $width[0];
        width $_->[0] => $width[1];
    }
    for (@abuse) {
        printf "%$width[0]d %.1f%% %$width[0]s",
            $_->[1], $_->[1]/$total*100, SpamReport::Annotate::user($_->[0]);
        my $tab; $tab++ if 1 < scalar(keys %{$data->{'forwarder_responsibility'}{$_->[0]}});
        for (keys %{$data->{'forwarder_responsibility'}{$_->[0]}}) {
            printf "%s$YELLOW%s$NULL -> $GREEN%s$NULL",
                ($tab ? "\n\t" : " :: "),
                $_,
                join(" ", keys %{$data->{'offserver_forwarders'}{$_}})
        }
        print "\n";
    }

    if ($omitted) {
        print "\n$omitted users were hidden"
            . (defined $ENV{RUSER} ? "; re-run with --full to see them.\n" : ".\n")
    }
}

sub note_forwarder_abuse {
    my @abuse = sort { $b->[1] <=> $a->[1] }
                map { [$_, List::Util::sum(values %{$data->{'forwarder_responsibility'}{$_}})] }
                keys %{$data->{'forwarder_responsibility'}};
    my $total = 0; $total += $_->[1] for @abuse;
    return unless $total;

    printf "\nThere were %s emails (to %d accounts) that were forwarded off-server.\n"
        . (defined $ENV{RUSER} ? "(for details, re-run with --forwarders)\n" : ''),
        commify($total), scalar(@abuse);
}

sub print_script_report {
    my $latest = SpamReport::Tracking::Scripts::latest();
    my @widths = map { length $_ } qw(# IP /16 GEO PATH NAME);
    my $time = time();
    my $total = 0; for (values %$latest) { $total += $_->{'count'} }
    for (keys %$latest) {
        width $latest->{$_}{'count'} => $widths[0];
        width $latest->{$_}{'ips'} => $widths[1];
        width scalar(keys(%{$latest->{$_}{'geo'}})) => $widths[2];
        width scalar(keys(%{$latest->{$_}{'path_variations'}})) => $widths[3];
        width scalar(keys(%{$latest->{$_}{'file_variations'}})) => $widths[4];
    }
    my @scripts = sort { $latest->{$b}{'count'} <=> $latest->{$a}{'count'} } keys %$latest;
    my $omitted = @scripts;
    unless ($data->{'OPTS'}{'full'}) { @scripts = grep { $latest->{$_}{'count'}/$total > 0.01 } @scripts }
    $omitted -= @scripts;
    printf "%$widths[0]s %$widths[1]s %$widths[2]s %$widths[3]s %$widths[4]s %$widths[5]s\n", 
        ("#"x$widths[0]), qw(IP /16 GEO PATH NAME);
    for (@scripts) {
        printf "%$widths[0]d %$widths[1]d %$widths[2]d %$widths[3]d %$widths[4]d %$widths[5]d %32s $GREEN%s$NULL %s %s\n",
            $latest->{$_}{'count'}, $latest->{$_}{'ips'}, $latest->{$_}{'ip16'},
            scalar(keys %{$latest->{$_}{'geo'}}), $latest->{$_}{'path_variations'}, $latest->{$_}{'file_variations'},
            $_, $latest->{$_}{'file'}, top_country($latest->{$_}{'geo'}, 'direct'),
            (($time - $latest->{$_}{'latest'} < 24 * 3600)
                ? ''
                : sprintf("$YELLOW%dd ago$NULL", ($time - $latest->{$_}{'latest'}) / (24 * 3600)))
    }
    if ($omitted) {
        print "\n$omitted scripts were hidden"
            . (defined $ENV{RUSER} ? "; re-run with --full to see them.\n" : ".\n")
    }
}

sub analyze_helos {
    for (values %{$data->{'mail_ids'}}) {
        next unless exists $_->{'helo'} && exists $_->{'who'} && $_->{'who'} !~ /\@/;
        next if defined($data->{'OPTS'}{'user'}) && $_->{'who'} ne $data->{'OPTS'}{'user'};
        $data->{'total_helos'}++;
        $data->{'helos'}{$_->{'who'}}{'count'}++;
        $data->{'helos'}{$_->{'who'}}{'helo'}{$_->{'helo'}}++;
        $data->{'helos'}{$_->{'who'}}{'IP'}{$1}++ if $_->{'helo'} =~ / \[((\d+\.\d+)\.\d+\.\d+)\]:\d+/;
        $data->{'helos'}{$_->{'who'}}{'/16'}{$2}++ if defined $2;
        $data->{'helos'}{$_->{'who'}}{'GEO'}{SpamReport::GeoIP::lookup($1)}++ if defined $1;
        $data->{'helos'}{$_->{'who'}}{'from'}{$_->{'sender'}}++ if defined $_->{'sender'};
    }
}

sub print_helo_report {
    my @widths = map { length $_ } qw(# % IP /16 GEO FROM USER);
    unless ($data->{'total_helos'}) { print "Nothing to report.\n"; return }
    for (keys %{$data->{'helos'}}) {
        width $data->{'helos'}{$_}{'count'} => $widths[0];
        width sprintf("%.1f", $data->{'helos'}{$_}{'count'} / $data->{'total_helos'} * 100) => $widths[1];
        width scalar(keys(%{$data->{'helos'}{$_}{'IP'}})) => $widths[2];
        width scalar(keys(%{$data->{'helos'}{$_}{'/16'}})) => $widths[3];
        width scalar(keys(%{$data->{'helos'}{$_}{'GEO'}})) => $widths[4];
        width scalar(keys(%{$data->{'helos'}{$_}{'from'}})) => $widths[5];
        width $_ => $widths[6];
    }
    printf "%$widths[0]s %$widths[1]s %$widths[2]s %$widths[3]s %$widths[4]s %$widths[5]s\n",
        ("#"x$widths[0]), ("%"x$widths[1]), qw(IP /16 GEO FROM);
    my @helos = sort { $data->{'helos'}{$b}{'count'} <=> $data->{'helos'}{$a}{'count'} }
                keys %{$data->{'helos'}};
    my $omitted = @helos;
    unless ($data->{'OPTS'}{'full'}) {
        @helos = grep { $data->{'helos'}{$_}{'count'} / $data->{'total_helos'} > 0.01 } @helos;
    }
    $omitted = @helos;
    for (@helos) {
        printf "%$widths[0]s %$widths[1].1f %$widths[2]s %$widths[3]s %$widths[4]s %$widths[5]s %$widths[6]s %s\n",
            $data->{'helos'}{$_}{'count'},
            $data->{'helos'}{$_}{'count'} / $data->{'total_helos'} * 100,
            scalar(keys(%{$data->{'helos'}{$_}{'IP'}})),
            scalar(keys(%{$data->{'helos'}{$_}{'/16'}})),
            scalar(keys(%{$data->{'helos'}{$_}{'GEO'}})),
            scalar(keys(%{$data->{'helos'}{$_}{'from'}})),
            $_,
            top_country($data->{'helos'}{$_}{'GEO'}, 'direct')
    }
    if ($omitted) {
        print "\n$omitted users were hidden"
            . (defined $ENV{RUSER} ? "; re-run with --full to see them.\n" : ".\n")
    }
}

sub print_script_info {
    my ($md5) = @_;
    my $tracking = SpamReport::Tracking::Scripts::paths($md5);
    my $width = 0;
    my $time = time();
    for (values %$tracking) { $width = length($_->{'count'}) if length($_->{'count'}) > $width }
    for (sort { $tracking->{$b}{'count'} <=> $tracking->{$a}{'count'} } keys %$tracking) {
        printf "%${width}d %s%s\n", $tracking->{$_}{'count'},
            SpamReport::Annotate::script($_),
            (($time - $tracking->{$_}{'latest'} < 24 * 3600)
                ? ''
                : sprintf(" $RED%dd ago$NULL", ($time - $tracking->{$_}{'latest'}) / (24 * 3600)))
    }
}

sub analyze_mailboxes {
    for my $mb (keys %{$data->{'mailbox_responsibility'}}) {
        next unless $mb =~ /(\S+?)@(\S+)/;
        my $user = $data->{'domain2user'}{$2};
        if ($user) {
            my $dir = "/home/$user/mail/$2/$1";
            if (-d $dir) {
                if (-C $dir < 30) {
                    $data->{'young_mailboxes'}{$dir}++
                }
            }
            else {
                $data->{'nonexistent_mailboxes'}{$mb}++;
                $data->{'nonexistent_mailbox_users'}{$user}++;
            }
        } else {
            $data->{'unhosted_domains'}{$mb}++;
        }
    }
}

sub percent_report {
    my ($h, $total, $limit, $title, $discarded, $annotate) = @_;
    return unless $total;
    my @list = sort { $h->{$a} <=> $h->{$b} } grep { $h->{$_} / $total > $limit } keys %$h;
    my @width = (0, 0);
    for (@list) {
        width $h->{$_} => $width[0];
        width sprintf("%.1f", 100*$h->{$_}/$total) => $width[1];
    }

    $discarded = sprintf(" (incl. %s emails discarded for hitting 500/hour limits)", commify($discarded))
        if $discarded;
    print "\nResponsibility for @{[commify($total)]} $title$discarded\n";
    for (reverse @list) {
        printf "%$width[0]d %$width[1].1f%% %s\n", $h->{$_}, 100*$h->{$_}/$total,
            $annotate->($_)
    }
}

sub print_responsibility_results {
    my ($emails, $bounces) = ($data->{'total_outgoing'}, $data->{'total_bounce'});
    my $cutoff = $data->{'OPTS'}{'r_cutoff'} / 100;
    my ($excl, $exclbounce);
    $excl = sprintf(" (excl. %s filtered emails)", commify($data->{'filtered_outgoing'}))
        if $data->{'filtered_outgoing'};
    $exclbounce = sprintf(" (excl. %s filtered bounces)", commify($data->{'filtered_bounce'}))
        if $data->{'filtered_bounce'};

    if (5 < keys(%{$data->{'owner_responsibility'}})) {
        # 5 to ignore random bad users on shared servers
        percent_report($data->{'owner_responsibility'}, $emails, $cutoff,
            "outgoing emails (owner)$excl", undef, sub {
                SpamReport::Annotate::owner(@_, "owner_responsibility", "responsibility")
        });
        percent_report($data->{'bounce_owner_responsibility'}, $bounces, $cutoff,
            "bouncebacks (owner)$exclbounce", undef, sub {
                SpamReport::Annotate::owner(@_, "bounce_owner_responsibility", "bounce_responsibility")
        });
    }
    percent_report($data->{'responsibility'}, $emails, $cutoff, "outgoing emails$excl", $data->{'total_discarded'}, \&SpamReport::Annotate::user);
    percent_report($data->{'bounce_responsibility'}, $bounces, $cutoff, "bouncebacks$exclbounce", undef, \&SpamReport::Annotate::user);
}

sub analyze_auth_mismatch {
    for (values %{$data->{'mail_ids'}}) {
        if (exists $_->{'ip'}) {
            $data->{'auth_mismatch'}{$_->{'sender'}}{'count'}++;
            $data->{'auth_mismatch'}{$_->{'sender'}}{'ip'}{$_->{'ip'}}++;
            $data->{'auth_mismatch'}{$_->{'sender'}}{'who'} = $_->{'who'};
            $data->{'auth_mismatch'}{$_->{'sender'}}{'country'}{SpamReport::GeoIP::lookup($_->{'ip'})}{$_->{'ip'}}++;
            $data->{'auth_mismatch'}{$_->{'sender'}}{'auth'}{$_->{'auth_sender'}}++
        }
    }
}

# $countries is a hashref of country names to
#   $direct : a number of hits
#  !$direct : a hash where the number of hits == keys of this hash
sub top_country {
    my ($countries, $direct) = @_;
    my @countries;
    if ($direct) {
        @countries = grep { defined $_ }
            (sort { $countries->{$b} <=> $countries->{$a} } keys %$countries)[0..2];
    } else {
        @countries = grep { defined $_ }
            (sort { scalar(keys(%{$countries->{$b}})) <=>
                    scalar(keys(%{$countries->{$a}})) } keys %$countries)[0..2];
    }
    for my $embargo (grep { exists $SpamReport::Annotate::embargo{$_} } keys %$countries) {
        push @countries, $embargo unless grep { $embargo eq $_ } @countries
    }
    if ($direct) {
        join " ", map { SpamReport::Annotate::country($_) .  ":" . $countries->{$_} } @countries;
    } else {
        join " ", map { SpamReport::Annotate::country($_) .  ":" . scalar(keys(%{$countries->{$_}})) } @countries;
    }
}

sub top_auth {
    my ($auths) = @_;
    my @auths = grep { defined $_ } (sort { $auths->{$b} <=> $auths->{$a} } keys %$auths)[0..2];
    join " ", map { "$GREEN$_$NULL:$auths->{$_}" } @auths;
}

sub print_auth_mismatch {
    print "\n${GREEN}Authorization$NULL vs. sender domain mismatches\n";
    my @widths = (0, 0, 0, 0);
    for (keys %{$data->{'auth_mismatch'}}) {
        my ($s, $i, $c, $u) = map { length $_ } (
            $_,
            scalar(keys(%{$data->{'auth_mismatch'}{$_}{'ip'}})),
            $data->{'auth_mismatch'}{$_}{'count'},
            $data->{'auth_mismatch'}{$_}{'who'}
        );
        setmax $c => $widths[0];
        setmax $i => $widths[1];
        setmax $u => $widths[2];
        setmax $s => $widths[3];
    }
    for (sort { $data->{'auth_mismatch'}{$b}{'count'} <=>
                $data->{'auth_mismatch'}{$a}{'count'} }
            keys %{$data->{'auth_mismatch'}}) {
        printf "%$widths[0]d %$widths[1]d %$widths[2]s %s %s %s\n",
            $data->{'auth_mismatch'}{$_}{'count'},
            scalar(keys(%{$data->{'auth_mismatch'}{$_}{'ip'}})),
            $data->{'auth_mismatch'}{$_}{'who'},
            $_,
            top_country($data->{'auth_mismatch'}{$_}{'country'}),
            top_auth($data->{'auth_mismatch'}{$_}{'auth'})
    }
}

my $hisource = qr/$RE{'spam'}{'hi_source'}/;
my $spamtld  = qr/$RE{'spam'}{'spammy_tld'}/;
my $hidest   = qr/$RE{'spam'}{'hi_destination'}/;
sub analyze_user_indicators {
    my ($emails, $bounces) = ($data->{'total_outgoing'}, $data->{'total_bounce'});
    my %users;
    my $cutoff = $data->{'OPTS'}{'r_cutoff'} / 100;
    for (keys %{$data->{'responsibility'}}) {
        $users{$_} = undef if $emails && $data->{'responsibility'}{$_} / $emails > $cutoff;
    }
    for (keys %{$data->{'bounce_responsibility'}}) {
        $users{$_} = undef if $bounces && $data->{'bounce_responsibility'}{$_} / $bounces > $cutoff;
    }
    for (values %{$data->{'mail_ids'}}) {
        my $user = $_->{'who'};
        next unless exists $users{$user};
        next if $_->{'type'} eq 'bounce';
        $users{$user}{'total'}++;
        if ($_->{'subject'} =~ /^Account Details for |^Activate user account|^Welcome to/) {
            $users{$user}{'botmail'}++
        }
        if ($_->{'subject'} =~ /^Cron /) {
            $users{$user}{'cronmail'}++;
        }
        if ($_->{'sender'} =~ /[^\@_]+_/) {
            $users{$user}{'underbar_mail'}++;
        }
        #if ($_->{'subject'} =~ /^(?:hello|hi)!?$/i or $_->{'subject'} eq '') {
        #    $data->{'special_indicators'}{$user}{'hi_malware'}++;
        #}
        if ($_->{'sender_domain'} =~ $hisource or
            $_->{'sender_domain'} =~ $spamtld) {
            $users{$user}{'badsender'}++;
        }
        if (grep { $_ =~ $hidest } @{$_->{'recipients'}}) {
            $users{$user}{'badrecipient'}++;
        }
        if ($_->{'subject'} =~ /^Your email requires verification verify#/) {
            $users{$user}{'boxtrapper'}++;
        }
    }
    my $recently = time() - 7 * 24 * 3600;
    my @history = reverse history_since($recently);
    for my $user (keys %users) {
        for (keys %{$data->{'outscript'}}) {
            $users{$user}{'outscript'} += $data->{'outscript'}{$_} if m,/home\d*/\Q$user\E/,
        }
        for (scalar(SpamReport::Tracking::Suspensions::tickets($user))) {
            if ($_) {
                $data->{'indicators'}{$user}{"abuse:$_"}++
            }
        }
        for (@history) {
            if ($_->[1] =~ /\Q$user/) {
                $data->{'in_history'}{$user} = $_->[0];
                last
            }
        }
        my $mtime = (stat("/home/$user/.security"))[9];
        if ($mtime > $recently) {
            $data->{'indicators'}{$user}{"security:" . ago($mtime, 1)}++;
        }
    }
    for my $login (keys %{$data->{'logins'}}) {
        next unless $data->{'logins'}{$login}{'indicate'};
        if ($login =~ /[\@+]([^\@+]+)$/ && exists $users{$data->{'domain2user'}{$1}}) {
            $data->{'indicators'}{$data->{'domain2user'}{$1}}{$login.':'.$data->{'logins'}{$login}{'total_logins'}."(IPs)"}++;
        }
    }
    for (keys %users) {
        next unless $users{$_}{'total'};
        if ($users{$_}{'botmail'} / $users{$_}{'total'} > 0.8) {
            $data->{'indicators'}{$_}{'bots?'}++;
        }
        if ($users{$_}{'underbar_mail'} / $users{$_}{'total'} > 0.8) {
            $data->{'indicators'}{$_}{'fake_accts?'}++;
        }
        if ($users{$_}{'badsender'} / $users{$_}{'total'} > 0.9) {
            $data->{'indicators'}{$_}{'bad_sender?'}++;
        }
        if ($users{$_}{'badrecipient'} / $users{$_}{'total'} > 0.9) {
            $data->{'indicators'}{$_}{'bad_recipients?'}++;
        }
        if ($users{$_}{'cronmail'} / $users{$_}{'total'} > 0.9) {
            $data->{'indicators'}{$_}{'cron?'}++;
        }
        if ($users{$_}{'outscript'} / $users{$_}{'total'} > 0.9) {
            $data->{'indicators'}{$_}{'script_comp?'}++;
        }
        for ($users{$_}{'boxtrapper'} / $users{$_}{'total'}) {
            if ($_ > 0.5) {
                $data->{'indicators'}{$_}{sprintf("boxtrapper:%.1f%%", $_*100)}++;
            }
        }
        if ($data->{'discarded_users'}{$_}) {
            $data->{'indicators'}{$_}{sprintf("discard:%.1f%%", $data->{'discarded_users'}{$_}/$users{$_}{'total'}*100)}++;
        }
    }
}

sub history_since {
    my ($since) = @_;
    my @history;
    my $skip;
    open my $f, '<', '/root/.bash_history' or return;
    my $date = localtime();
    while ($_ = <$f>) {
        if (/^\#(\d+)/) { if ($1 < $since) { $skip++ } else { $date = $1 } next }
        if ($skip) { undef $skip; next }
        push @history, [$date, $_]
    }
    close $f;
    @history;
}

sub print_recipient_results {
    my @widths = (0, 0);
    for (values %{$data->{'suspects'}{'num_recipients'}}) {
        my ($em, $ad) = (length($_->{'emails'}), length($_->{'addresses'}));
        setmax $em => $widths[0];
        setmax $ad => $widths[1];
    }
    
    my %h = %{$data->{'suspects'}{'num_recipients'}};
    for (reverse sort { $h{$a}->{ratio} <=> $h{$b}->{ratio} } keys %h) {
        printf "%$widths[0]d %$widths[1]d %.4f num_recipients: $_\n",
            $h{$_}->{'emails'}, $h{$_}->{'addresses'}, $h{$_}->{'ratio'};
    }
}

sub scriptlimit {
    my ($h, $total, $per) = @_;
    return unless $total;
    my @r = grep { $h->{$_}/$total > $per } keys %$h;
    map { [$_, $h->{$_}, $total] } sort { $h->{$a} <=> $h->{$b} } grep { defined $_ } @r[0..4]
}

sub suppressed_scriptdirs {
    my ($h) = @_;
    DIR: for my $dir (keys %{$data->{'scriptdirs'}}) {
        for (keys %{$data->{'outscript'}}) {
            next DIR if $_ =~ m,^$dir/*[^/]+$,
                # && $data->{'outscript'}{$_}/$data->{'scriptdirs'}{$dir} > 0.9
        }
        $h->{$dir} = $data->{'scriptdirs'}{$dir};
    }
}

sub print_script_results {
    my %dirs; suppressed_scriptdirs(\%dirs);
    my $scriptdirs = 0; $scriptdirs += $dirs{$_} for keys %dirs;
    my $script = 0; $script += $data->{'outscript'}{$_} for keys %{$data->{'outscript'}};
    my @r = (scriptlimit(\%dirs, $scriptdirs, 0.1),
             scriptlimit($data->{'outscript'}, $script, 0.1));
    my @width = (0, 0);
    for (@r) {
        my $frac = length(sprintf "%.1f", 100*$_->[1]/$_->[2]);
        width $_->[1] => $width[0];
        setmax $frac => $width[1];
    }

    print "\nResponsibility for @{[commify($scriptdirs)]} script dirs and @{[commify($script)]} scripts\n";
    for (reverse @r) {
        printf "%$width[0]d %$width[1].1f%% %s\n", $_->[1], 100*$_->[1]/$_->[2],
            SpamReport::Annotate::script($_->[0])
    }
    #for (sort { $data->{'script'}{$a} <=> $data->{'script'}{$b} } keys %{$data->{'script'}}) {
    #    print "$data->{'script'}{$_} $_\n"
    #}
    #for (sort { $data->{'script_ip'}{$a} <=> $data->{'script'}{$b} } keys %{$data->{'script_ip'}}) {
    #    print "$data->{'script_ip'}{$_} $_\n"
    #}
}

sub print_login_results {
    print "\nSuspect logins\n";
    my @width = (0, 0, 0, 0);
    my %h; $h{$_} = $data->{'logins'}{$_} for grep { $data->{'logins'}{$_}{'suspect'} } keys %{$data->{'logins'}};
    for (keys %h) {
        my ($lo, $pr) = map { length($_) } ($h{$_}{'total_logins'}, scalar(keys %{$h{$_}{'logins_from'}}));
        my $wh = /[\@+]([^\@+]+)/ ? length($h{$_}{'who'} = $data->{'domain2user'}{$1}) : 0;
        setmax $lo => $width[0];
        setmax $pr => $width[1];
        setmax $wh => $width[2];
        setmax $_ => $width[3];
    }
    $width[3] = 30 if $width[3] > 30;  # XXX
    for my $login (reverse sort { $h{$a}{'total_logins'} <=> $h{$b}{'total_logins'} } keys %h) {
        (my $short = $login) =~ s/^(.{27}).*/$1\e\e\e/; # XXX
        my @ips = sort { $h{$login}{'logins_from'}{$b} <=> $h{$login}{'logins_from'}{$a} } keys %{$h{$login}{'logins_from'}};
        my @counts = map { $h{$login}{'logins_from'}{$_} } @ips;
        my $line = sprintf "%$width[0]d %$width[2]s %$width[1]d %$width[3]s %s(%d) %s(%d) %s(%d) :: %s\n",
            $h{$login}{'total_logins'}, $h{$login}{'who'}, scalar(keys %{$h{$login}{'logins_from'}}),
            $short,
            "$MAGENTA$ips[0]$NULL", $counts[0],
            "$YELLOW$ips[1]$NULL", $counts[1],
            "$GREEN$ips[2]$NULL", $counts[2], # join(" ", map { $ips[$_].':'.$counts[$_] } 3..$#ips)
            top_country($h{$login}{'country'});
        $line =~ s/\e\e\e/$RED...$NULL/g;
        print $line
    }
}

sub print_queue_results {
    my @results;
    my $output;

    for my $field (keys %{$data->{'queue_top'}}) {
        push @results, top(fieldcolor($field) => $data->{'queue_top'}{$field})
    }

    print "\nResponsibility for @{[commify($data->{'total_queue'})]} queued emails (excl. @{[commify($data->{'boxtrapper_queue'})]} boxtrapper; @{[commify($data->{'local_queue'})]} local):\n";
    
    # display results with more related emails than 3% of the number of emails in the queue
    # ... or if this results in no output, display all fields
    for my $sig (0.03 * $data->{'total_queue'}, 1) {
        for (reverse sort { $a->[0] <=> $b->[0] } grep { $_->[0] > $sig } @results) {
            $output = 1;
            print "$_->[0] $_->[1]\n"
        }
        last if $output; 
    }
}

my %user_tests = (
    bounce_recipient => sub { exists $_[0]->{'recipient_users'}{$_[1]} },
    bounce_source => sub { exists $_[0]->{'source'}{$_[1]} },
    who => sub {
        return 1 if $_[0]->{'who'} eq $_[1];
        if ($_[1] eq $data->{'domain2user'}{$_[0]->{'sender_domain'}}) {
            $data->{'crossauth'}{$_[1]}{$_[0]->{'who'}}++;
            return 1;
        }
        undef;
    },
    path => sub { $_[0] =~ m,^/[^/]+/$_[1]/, }
);
my %root_tests = (
    bounce_recipient => sub { 1 },
    bounce_source => sub { 1 },
    who => sub { 1 },
    path => sub { 1 },
);
my %reseller_tests = do {
    my %resolds;
    (
        set_resolds => sub { %resolds = (); $resolds{$_} = 1 for @_ },
        bounce_recipient => sub {
            for (keys %{$_[0]->{'recipient_users'}}) {
                return 1 if exists $resolds{$_}
            }
            return
        },
        bounce_source => sub {
            for (keys %{$_[0]->{'source'}}) {
                return 1 if exists $resolds{$_}
            }
            return
        },
        who => sub { exists $resolds{$_[0]->{'who'}} },
        path => sub {
            return unless $_[0] =~ m,^/[^/]+/([^/]+)/,;
            return exists $resolds{$1}
        }
    )
};

sub analyze_user_results {
    my ($user, $isreseller) = @_;
    my ($sent, $bounce, $queued, $boxtrapper) = (0, 0, 0);
    my %sent;
    my %bounce;
    my %sent_as;
    my %ips;
    my %cwd;
    my %script;
    my %recip;
    my %subject;
    my $tests = \%user_tests;
    if ($user eq 'root') {
        $tests = \%root_tests
    } elsif ($isreseller) {
        $tests = \%reseller_tests;
        $tests->{'set_resolds'}(@{$data->{'owner2user'}{$user}});
    }

    my %dirs; suppressed_scriptdirs(\%dirs);

    for my $email (values %{$data->{'mail_ids'}}) {
        if ($email->{'type'} eq 'bounce' && $tests->{'bounce_recipient'}($email, $user)) {
            $bounce++;
            $bounce{$email->{'recipients'}->[0]}++;
            $queued++ if $email->{'in_queue'};
        }
        elsif ($email->{'type'} eq 'bounce' && $tests->{'bounce_source'}($email, $user)) {
            $bounce++;
            $bounce{$email->{'source'}}++;
            $queued++ if $email->{'in_queue'};
        }
        elsif ($tests->{'who'}($email, $user)) {
            $sent++;
            $sent_as{$email->{'sender'}}++;
            $queued++ if $email->{'in_queue'};
            $boxtrapper++ if $email->{'boxtrapper'};
            if ($email->{'host_auth'} =~ /^dovecot_/) {
                $sent{$email->{'host_auth'} . ':' . $email->{'auth_sender'}}++;
            } elsif ($email->{'auth_sender'}) {
                $sent{$email->{'auth_sender'}}++;
            } elsif ($email->{'received_protocol'} eq 'local' && $email->{'ident'}) {
                $sent{$email->{'ident'}}++;
            }
            if (exists $email->{'host_address'}) {
                $ips{$email->{'host_address'}}++
            }
            for (@{$email->{'recipients'}}) {
                $recip{$_}++
            }
            if (exists $email->{'subject'}) {
                $subject{$email->{'subject'}}++
            }
        }
    }
    for (keys %dirs) {
        next unless $tests->{'path'}($_, $user);
        $cwd{$_} += $dirs{$_}
    }
    for (keys %{$data->{'outscript'}}) {
        next unless $tests->{'path'}($_, $user);
        $script{$_} += $data->{'outscript'}{$_}
    }

    $data->{'suspects'}{'users'}{$user} = {
        sent => $sent || "NaN",
        bounce => $bounce,
        queued => $queued,
        boxtrapper => $boxtrapper,
        sent_accounts => \%sent,
        bounce_addresses => \%bounce,
        sent_addresses => \%sent_as,
        ips => \%ips,
        cwd => \%cwd,
        script => \%script,
        recipients => \%recip,
        subject => \%subject,
    };
}

# modified http://www.perlmonks.org/?node_id=653
# if given a hashref, commify the number of keys
sub commify {
    my $input = shift;
    $input = scalar(keys %$input) if ref $input eq 'HASH';
    $input = reverse $input;
    $input =~ s<(\d\d\d)(?=\d)(?!\d*\.)><$1,>g;
    $input = reverse $input;
    $input
}

sub sample {
    my ($h, $title) = @_;
    (join '' => 
        map { "$_: $h->{$_}\n" }
        grep { defined $_ }
        (sort { $h->{$b} <=> $h->{$a} } keys %$h)[0..14])
    . remainder($h, $title)
}

sub topsubjects {
    my ($h) = @_;
    my $width = 0;
    for (values %$h) { $width = length($_) if $width < length($_) }
    (join "\n",
        map { sprintf "%${width}d %s", $h->{$_}, $_ }
        grep { defined $_ }
        (sort { $h->{$b} <=> $h->{$a} } keys %$h)[0..14])
}

sub remainder {
    my ($h, $title) = @_;
    my $rest = keys(%$h) - 15;
    return if $rest < 1;
    return "\nThere were @{[commify($rest)]} additional $title trimmed.\n"
}

sub boxtrapper {
    my ($u, $total) = @_;
    return unless $u->{'boxtrapper'};
    return <<BOX
Boxtrapper was responsible for @{[commify($u->{'boxtrapper'})]} sent emails, or @{[sprintf "%.2f%%", 100*$u->{'boxtrapper'}/$total]} of the emails.

BOX
}

sub php_scripts {
    my ($u) = @_;
    my $r;
    if ((values(%{$u->{'cwd'}}))[0]) {
        $r .= <<PHP
Current working directories:
------------
@{[sample($u->{'cwd'}, "working directories")]}
PHP
    }
    if ((values(%{$u->{'script'}}))[0]) {
        $r .= <<PHP
PHP Scripts:
------------
@{[sample($u->{'script'}, "PHP scripts")]}
PHP
    }
    $r
}

{
    my $time = time();
    my %units = (
        0 => {days => " days", hours => " hours"},
        1 => {days => "d", hours => "h"}
    );
    sub ago {
        my $delta = ($time - $_[0]) / (24 * 3600);
        if ($delta > 1) {
            sprintf "%.1f$units{$_[1]}{days}", $delta
        } else {
            sprintf "%.1f$units{$_[1]}{hours}", ($time - $_[0]) / 3600
        }
    }
}

sub user_ticket_report {
    my ($user, $isreseller) = @_;
    $isreseller = 1 if $user eq 'root';
    my @tickets;
    my $r = "----------------------------------------\n\n";
    my @widths = (0, 0, 0, 0);
    for my $u (sort $user, @{$data->{'owner2user'}{$user}}) {
        my @t = SpamReport::Tracking::Suspensions::tickets($u);
        next unless @t;
        for my $t (@t) {
            if ($data->{'suspensions'}{$u}{$t}{'enable'} && $data->{'suspensions'}{$u}{$t}{'disable'}) {
                push @tickets, [$u, $t, (map { ago($data->{'suspensions'}{$u}{$t}{$_}, 0) . " ago" } qw(enable disable)),
                                $data->{'suspensions'}{$u}{$t}{'disable'}]
            }
            elsif ($data->{'suspensions'}{$u}{$t}{'disable'}) {
                push @tickets, [$u, $t, ago($data->{'suspensions'}{$u}{$t}{'disable'}, 0) . " ago", '', 
                                $data->{'suspensions'}{$u}{$t}{'disable'}]
            }
            else { # enable only --> disable predates abusetool logs
                push @tickets, [$u, $t, '(prehistory)', ago($data->{'suspensions'}{$u}{$t}{'enable'}, 0) . " ago",
                                $data->{'suspensions'}{$u}{$t}{'enable'}]
            }
        }
    }
    for (@tickets) {
        width $_->[0] => $widths[0];
        width $_->[1] => $widths[1];
        width $_->[2] => $widths[2];
        width $_->[3] => $widths[3];
    }
    for (sort { $a->[4] <=> $b->[4] } @tickets) {
        $r .= sprintf("%s%s%$widths[1]s$NULL : %$widths[2]s -> %$widths[3]s : %s\n",
                ($isreseller ? sprintf("%$widths[0]s : ", $_->[0]) : ''),
                ($_->[3] ? '' : $RED),
                $_->[1], $_->[2], $_->[3], scalar(localtime($_->[4])))
    }
    $r .= "\n";
    $r
}

sub user_hour_report {
    my ($user, $isreseller) = @_;
    return unless $data->{'OPTS'}{'hourly_report'};
    my $r = "----------------------------------------\n\n";
    my $volumes;
    if ($user eq 'root') {
        for my $u (keys %{$data->{'hourly_volume'}}) {
            for (keys %{$data->{'hourly_volume'}{$u}}) {
                $volumes->{$_} += $data->{'hourly_volume'}{$u}{$_}
            }
        }
    }
    elsif ($isreseller) {
        for my $resold ($user, @{$data->{'owner2user'}{$user}}) {
            for (keys %{$data->{'hourly_volume'}{$resold}}) {
                $volumes->{$_} += $data->{'hourly_volume'}{$resold}{$_}
            }
        }
    }
    else { $volumes = $data->{'hourly_volume'}{$user} }
    for (sort keys %$volumes) {
        $r .= "$_: " . commify($volumes->{$_}) . "\n"
    }
    $r .= "\n";
    $r
}

sub print_user_results {
    my ($user, $isreseller) = @_;
    my $u = $data->{'suspects'}{'users'}{$user}
        or die "No information about $user";

    if (!$u->{'sent'}) {
        die "$user sent no emails in the period examined.\n"
    }

    my %sent_as = %{$u->{'sent_addresses'}};
    $sent_as{$_} += $u->{'bounce_addresses'}{$_} for keys %{$u->{'bounce_addresses'}};

    my $total = $u->{'sent'} + $u->{'bounce'};
    $total ||= 'NaN';
    $u->{'boxtrapper'} ||= 0;

    print <<"REPORT";
Reference: spamreport
   Server: $hostname
     User: $user

@{[user_ticket_report($user, $isreseller)]}@{[user_hour_report($user, $isreseller)]}----------------------------------------

User sent approximately @{[commify($u->{'sent'})]} messages to @{[commify($u->{'recipients'})]} unique recipients.
There were @{[commify($u->{'bounce'})]} bounces on @{[commify($u->{'bounce_addresses'})]} unique addresses, @{[sprintf "%.2f%%", 100*$u->{'bounce'}/$total]} of the emails.

@{[boxtrapper($u, $total)]}Email addresses sent from:
--------------------------
@{[sample(\%sent_as, "sender addresses")]}
Logins used to send mail:
-------------------------
@{[sample($u->{'sent_accounts'}, "logins")]}
@{[php_scripts($u)]}Random recipient addresses:
---------------------------
@{[join "\n",
    grep { defined $_ }
    (List::Util::shuffle(keys %{$u->{'recipients'}}))[0..15]]}

Top recipients:
---------------
@{[sample($u->{'recipients'}, "recipients")]}
Top subjects:
-------------
@{[topsubjects($u->{'subject'})]}

Total number of distinct subjects: @{[commify($u->{'subject'})]}

Emails found in queue:
----------------------
User: @{[commify($u->{'queued'})]}, Total: @{[commify($data->{'total_queue'})]}

This user was responsible for @{[sprintf "%.2f%%", 100*($u->{'sent'}+$u->{'bounce'})/(scalar(keys %{$data->{'mail_ids'}}) || 'NaN')]} of the emails found.@{[scalar(keys(%{$data->{'crossauth'}{$user}})) ? "\n${MAGENTA}Some of this user's email may be getting authorized by an another user's credentials.$NULL" : '']}


REPORT
}

sub top {
    my ($type, $h) = @_;
    map { [$h->{$_}, "$type: $_"] } keys %$h
}

{
    SpamReport::ANSIColor::suppress() if exists($ENV{nocolors}) || !-t\*STDOUT;

    my %fieldcolors = (
        source => $YELLOW,
        auth_id => $RED,
        ident => $YELLOW,
        auth_sender => $RED,
        sender_domain => $GREEN,
        sender => $GREEN,
        recipient_domains => $CYAN,
        recipient_users => $CYAN,
    );

    sub fieldcolor {
        my ($field) = @_;
        return $field unless exists $fieldcolors{$field};
        $fieldcolors{$field} . $field . $NULL
    }
}

1;
} # end SpamReport::Output
BEGIN {
$INC{'SpamReport/Output.pm'} = '/dev/null';
}

BEGIN {
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
BEGIN {
$INC{'File/Nonblock.pm'} = '/dev/null';
}

BEGIN {
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
}
BEGIN {
$INC{'SpamReport/Cpanel.pm'} = '/dev/null';
}

BEGIN {
package SpamReport::Exim;
use common::sense;
use SpamReport::Data;
use SpamReport::Tracking::Scripts;

use vars qw/$VERSION/;
$VERSION = '2016022601';

use Time::Local;
use Regexp::Common qw( Exim );

my @indicators = ( '<=', '=>', '->', '>>', '*>', 'SMTP connection outbound', '**', '==', 'Completed' );
my @statuses = qw( input output continued cutthrough inhibited connect deferred bounced complete );
my @labels = qw( ident received_protocol auth_id auth_sender
                     helo_name host_address host_auth interface_address frozen);
my @flags  = qw( deliver_firsttime host_lookup_failed local localerror );

# https://github.com/mailcheck/mailcheck/wiki/List-of-Popular-Domains
my ($dubious_domains) = map { qr/^(?:$_)$/i } join "|", map { quotemeta $_ } (
    qw( aol.com att.net comcast.net facebook.com gmail.com gmx.com googlemail.com
        google.com hotmail.com hotmail.co.uk mac.com me.com mail.com msn.com
        live.com sbcglobal.net verizon.net yahoo.com yahoo.co.uk ),

    # Other global domains
    qw( email.com games.com gmx.net hush.com hushmail.com icloud.com inbox.com
        lavabit.com love.com outlook.com pobox.com rocketmail.com
        safe-mail.net wow.com ygm.com ymail.com zoho.com fastmail.fm ),

    # United States ISP domains
    qw( bellsouth.net charter.net comcast.net cox.net earthlink.net juno.com ),

    # British ISP domains
    qw( btinternet.com virginmedia.com blueyonder.co.uk freeserve.co.uk live.co.uk
        ntlworld.com o2.co.uk orange.net sky.com talktalk.co.uk tiscali.co.uk
        virgin.net wanadoo.co.uk bt.com ),

    # Domains used in Asia
    qw( sina.com qq.com naver.com hanmail.net daum.net nate.com yahoo.co.jp
        yahoo.co.kr yahoo.co.id yahoo.co.in yahoo.com.sg yahoo.com.ph ),

    # French ISP domains
    qw( hotmail.fr live.fr laposte.net yahoo.fr wanadoo.fr orange.fr gmx.fr
        sfr.fr neuf.fr free.fr ),

    # German ISP domains
    qw( gmx.de hotmail.de live.de online.de t-online.de web.de yahoo.de ),

    # Russian ISP domains
    qw( mail.ru rambler.ru yandex.ru ya.ru list.ru ),

    # Belgian ISP domains
    qw( hotmail.be live.be skynet.be voo.be tvcablenet.be telenet.be ),

    # Argentinian ISP domains
    qw( hotmail.com.ar live.com.ar yahoo.com.ar fibertel.com.ar speedy.com.ar
        arnet.com.ar ),

    # Domains used in Mexico
    qw( hotmail.com gmail.com yahoo.com.mx live.com.mx yahoo.com hotmail.es
        live.com hotmail.com.mx prodigy.net.mx msn.com ),
);
    

# glob() performs unnecessary lstats for each file in the queue
# -f and -M and -M for glob() -> up to four stat syscalls per file.
# this subroutine performs no stats at all.
# the time range checks are dropped: if it's in the queue, it's of interest
sub email_header_files {
    my $queue_dir = '/var/spool/exim/input';
    my @headers;
    opendir my $d1, $queue_dir or die "Unable to open $queue_dir : $!";
    QUEUES: for my $subdir (readdir($d1)) {
        next if $subdir =~ /^\./;
        opendir my $d2, "$queue_dir/$subdir" or next;
        for (readdir($d2)) {
            if (/-H$/) {
                push @headers, "$queue_dir/$subdir/$_";
            }
        }
        closedir $d2;
    }
    closedir $d1;
    @headers
}

sub parse_queued_mail_data {
    my ($start_time, $end_time) = @_;

    my @new_mail = email_header_files();
    for my $i (0..$#new_mail) {
        my $line_no = 0;
        my $tree_start = 0;
        my $eod = 0;
        my $num_recipients = 0;
        my @recipients;
        my ($mail_id) = $new_mail[$i] =~ m{/([^/]+)-H};
        my $new_email;

        # this rigamorale avoids: readline() on closed filehandle $fh at spamreport...
        my @lines;
        eval {
                open my $fh, '<', $new_mail[$i];
                @lines = <$fh>;
                close $fh;
        }; next if $@;

        unless (exists $data->{'mail_ids'}{$mail_id}) {
            $new_email = 1;
        }
        %{$data->{'mail_ids'}{$mail_id}} = map {
            chomp;
            $line_no++;
    
            if ( m/^-(ident|received_protocol|auth_id|auth_sender|helo_name|host_address|host_auth|interface_address|frozen)\s+(.*)$/ ) {
                my $key = $1;
                my $val = lc($2);
                $val =~ s/((?:\d{1,3}\.){3}\d{1,3})\.\d+/$1/ if ($key eq 'host_address');
                ($key => $val);
            }
            elsif ( m/^-(deliver_firsttime|host_lookup_failed|local|localerror)/ ) {
                ($1 => 1);
            }
            elsif ( $line_no == 3 ) {
                my $sender = $_;
                $sender =~ s/<|>//g;
                ( 'sender' => lc($sender) || 'mailer-daemon' );
            }
            elsif ( m/^(?:[YN]{2}\s+|XX$)/ ) {
                $tree_start = $line_no;
                ();
            }
            elsif ( m/^(\d+)$/ and $tree_start ) {
                $eod = $line_no;
                $num_recipients = $1;
                ('num_recipients' => $num_recipients);
            }
            elsif ( $eod and /^\d+\s+X-PHP-Script: (\S+) for (\S+)/ ) {
                ('script' => $1, 'script_ip' => $2);
            }
            elsif ( $eod and /^\d+\s+X-Boxtrapper:/ ) {
                ('boxtrapper' => 1);
            }
            elsif ( /^\d+\s+Subject: (.*)/ ) {
                ('subject' => $1);
            }
            elsif ( $eod and ( $line_no - $eod <= $num_recipients) ) {
                push @recipients, lc($_);
                ();
            }
            elsif ( $eod and ( $line_no - $eod > $num_recipients) ) {
                ('recipients' => \@recipients);
            }
            else {
                ();
            }
            
        } @lines;

        if (exists $data->{'mail_ids'}{$mail_id}{'boxtrapper'}) {
            # we don't care about boxtrapper emails
            $data->{'boxtrapper_queue'}++;
            delete $data->{'mail_ids'}{$mail_id};
            next;
        }

        my $h_ref = $data->{'mail_ids'}{$mail_id};
        my ($type, $source) = $h_ref->{'sender'} eq 'mailer-daemon'   ? ('bounce', $h_ref->{'helo_name'})
                            : exists $h_ref->{'local'}                ? ('local', $h_ref->{'ident'})
                            : $h_ref->{'host_auth'} =~ m/^dovecot_.*/ ? ('login', $h_ref->{'auth_id'})
                                                                      : ('relay', $h_ref->{'helo_name'});
        $data->{'total_bounce'}++ if $type eq 'bounce';

        my $state = $h_ref->{'deliver_firsttime'} ? 'queued'
                  : $h_ref->{'frozen'}            ? 'frozen'
                                                  : 'thawed';

        $h_ref->{'type'} = $type;
        $h_ref->{'source'} = $source;
        $h_ref->{'state'} = $state;
        $h_ref->{'location'} = 'queue';
    
        ($h_ref->{'sender_domain'}) = $h_ref->{'sender'} =~ m/@(.*)$/;

        if ($h_ref->{'type'} ne 'bounce' && exists($data->{'domain2user'}{lc($h_ref->{'sender_domain'})})) {
            # not a bounce and for a local domain?  it may be an issue but we don't care here
            $data->{'local_queue'}++;
            delete $data->{'mail_ids'}{$mail_id};
            next;
        }

        for (@{$h_ref->{'recipients'}}) {
            if ( $_ =~ m/@(.*)$/ ) {
                $h_ref->{'recipient_domains'}{$1}++;
                if (exists $data->{'domain2user'}{$1}) {
                    $h_ref->{'recipient_users'}{$data->{'domain2user'}{$1}}++
                }
            }
        }
    
        for (who($h_ref)) {
            $h_ref->{'who'} = $_;
            last if /@/ or !$new_email;
            $data->{'responsibility'}{$_}++;
            $data->{'owner_responsibility'}{$data->{'user2owner'}{$_}}++
                if exists $data->{'user2owner'}{$_}
                && $data->{'user2owner'}{$_} ne 'root'
        }
        $h_ref->{'in_queue'} = 1;
        $data->{'total_queue'}++;
    }
}

my $eximinfoscript = qr/$RE{'exim'}{'info'}{'script'}/;
sub parse_exim_mainlog {
    my ($lines, $year, $end_time, $in_zone) = @_;
    my @lines = @$lines;
    my %days = %{$data->{'OPTS'}{'exim_days'}};
    if ($data->{'OPTS'}{'datelimit'} eq 'not today') {
        delete $days{$data->{'OPTS'}{'exim_today'}};
    }
    elsif ($data->{'OPTS'}{'datelimit'} eq 'only today') {
        %days = ($data->{'OPTS'}{'exim_today'} => 1);
    }

    unless ($in_zone->[0]) {
        if (exists $days{substr($lines[0],0,10)} or
            exists $days{substr($lines[$#lines],0,10)}) {
            $in_zone->[0] = 1
        }
        else {
            return
        }
    }
    for my $line ( @lines ) {
        unless (exists $days{substr($line,0,10)}) {
            $in_zone->[0] = 0;
            return
        }

        if ( substr($line,20,4) eq 'cwd=' && $line =~ $eximinfoscript ) {
            $data->{'scriptdirs'}{$1}++;
            next
        }
        my $mailid = substr($line,20,16);
        
        if (substr($line,37,24) eq 'SMTP connection outbound') {
            next unless $line =~ / I=(\S+) S=\S+ F=(.+)/;
            $data->{'outscript'}{$2}++;
            SpamReport::Tracking::Scripts::script($2, $1);
        }
        elsif (substr($line,37,5) eq '<= <>') {
            $line =~ s/T="(.*?)(?<!\\)" //;
            my $subject = $1;  # only used on authorized 'bounces'
            next unless $line =~ /.*for (.*)$/;  # leading .* causes it to backtrack from the right
            my @to = split / /, $1;
            $line =~ / S=(\S+)/; for my $script ($1) {
                if (defined $script && $script !~ /@/ && $script =~ /\D/) {
                    $data->{'mail_ids'}{$mailid}{'script'} = $script;
                    $data->{'script'}{$script}++;
                }
            }
            $data->{'mail_ids'}{$mailid}{'recipients'} = \@to;
            if ($line =~ / A=dovecot_\S+:([^\@+\s]+(?:[\@+](\S+))?)/) {
                # authenticated bounces!
                $data->{'mail_ids'}{$mailid}{'auth_sender'} = $1;
                my $user = $1;
                if (defined $2) {
                    $user = $data->{'domain2user'}{$2};
                    $data->{'mail_ids'}{$mailid}{'auth_sender_domain'} = $2;
                    $data->{'domain_responsibility'}{$2}++;
                    $data->{'mailbox_responsibility'}{$1}++;
                }
                $data->{'bounce_responsibility'}{$user}++;
                $data->{'mail_ids'}{$mailid}{'who'} = $user;
                $data->{'mail_ids'}{$mailid}{'subject'} = $subject if defined $subject;
            }
            elsif (@to == 1 && $to[0] =~ /\@(\S+)/ and exists $data->{'domain2user'}{$1}) {
                my $user = $data->{'domain2user'}{$1};
                $data->{'domain_responsibility'}{$1}++;
                $data->{'mailbox_responsibility'}{$to[0]}++;
                $data->{'bounce_responsibility'}{$user}++;
                $data->{'bounce_owner_responsibility'}{$data->{'user2owner'}{$user}}++
                        if exists $data->{'user2owner'}{$user}
                               && $data->{'user2owner'}{$user} ne 'root';
                $data->{'mail_ids'}{$mailid}{'recipient_users'}{$user}++;
                $data->{'mail_ids'}{$mailid}{'who'} = $user;
            }
            $data->{'mail_ids'}{$mailid}{'type'} = 'bounce';
            $data->{'total_bounce'}++;
        }
        elsif (substr($line,37,2) eq '<=' && $line =~ s/T="(.*?)(?<!\\)" //) {
            my $subject = $1;
            $line =~ /<= (\S+)/;
            my $from = $1;
            $line =~ /.*for (.*)$/;  # .* causes it to backtrack from the right
            my $to = $1;
            my @to = split / /, $to;
            my @to_domain = grep { defined $_ } map { /@(.*)/ && $1 } @to;
            if ($to !~ tr/@//) {
                # this is to a local users, only.  probably cronjob or like.
                # discard.
                delete $data->{'mail_ids'}{$mailid};
                next;
            }
            $data->{'mail_ids'}{$mailid}{'recipients'} = \@to if @to;
            $data->{'mail_ids'}{$mailid}{'sender'} = $from;
            my $from_domain;
            if ($from =~ /\S+?[\@+](\S+)/) {
                $from_domain = $1;
                $data->{'mail_ids'}{$mailid}{'sender_domain'} = $from_domain;
            }
            $data->{'mail_ids'}{$mailid}{'subject'} = $subject;
            if ($line =~ / A=dovecot_\S+:([^\@+\s]+(?:[\@+](\S+))?)/) {
                $data->{'mail_ids'}{$mailid}{'auth_sender'} = $1;
                $data->{'mail_ids'}{$mailid}{'auth_sender_domain'} = $2 if defined $2;
            }
            $data->{'mail_ids'}{$mailid}{'received_protocol'} = $1 if $line =~ / P=(\S+)/;
            $data->{'mail_ids'}{$mailid}{'ident'} = $1 if $line =~ / U=(\S+)/;
            $data->{'mail_ids'}{$mailid}{'who'} = who($data->{'mail_ids'}{$mailid});

            # this first test is a little unusual
            # 1. it prevents the following tests from deleting the email
            # 2. it assigns an IP, which is also the unique trigger for auth_mismatch
            # 3. it prevents the responsibility tracking in the final 'else'
            #
            if (exists $data->{'mail_ids'}{$mailid}{'sender_domain'} &&
                exists $data->{'mail_ids'}{$mailid}{'auth_sender_domain'} &&
                lc($data->{'mail_ids'}{$mailid}{'sender_domain'}) ne
                lc($data->{'mail_ids'}{$mailid}{'auth_sender_domain'}) && 
                $line =~ / A=dovecot/ &&
                $line =~ /\[([^\s\]]+)\]:\d+ I=/) {
                $data->{'mail_ids'}{$mailid}{'ip'} = $1;
            #}
            #elsif (!exists($data->{'mail_ids'}{$mailid}{'auth_sender'})  # not locally authed
            #    && !exists($data->{'mail_ids'}{$mailid}{'ident'})     # not ID'd as a local user
            #    && !exists($data->{'domain2user'}{lc($from)})  # sender domain is remote
            #    && !grep({ !exists($data->{'domain2user'}{lc($_)}) } @to_domain) ) {  # recipient domains are local
            #    # then this is an incoming email and we don't care about it
            #    delete $data->{'mail_ids'}{$mailid};
            #} elsif (@{$data->{'mail_ids'}{$mailid}{'recipients'}} ==
            #       grep { $_ =~ /\@\Q$data->{'mail_ids'}{$mailid}{'sender_domain'}\E$/i }
            #       @{$data->{'mail_ids'}{$mailid}{'recipients'}}) {
            #    # if the number of recipients is the same as the number of
            #    # recipients that are to the sender domain, which is local,
            #    # then we don't care.  people can spam themselves all they
            #    # want.
            #    delete $data->{'mail_ids'}{$mailid};
            } elsif (grep { exists($data->{'offserver_forwarders'}{$_}) } @to) {
                for my $forwarder (grep { exists($data->{'offserver_forwarders'}{$_}) } @to) {
                    next unless $forwarder =~ /[\@+]([^\@+]+)$/ && exists $data->{'domain2user'}{$1};
                    $data->{'forwarder_responsibility'}{$data->{'domain2user'}{$1}}{$forwarder}++;
                }
            } elsif (!grep({ !exists($data->{'domain2user'}{lc($_)}) } @to_domain)) {
                # actually just go ahead and drop all mail that's only to local addresses
                delete $data->{'mail_ids'}{$mailid};
            } else {
                $data->{'mail_ids'}{$mailid}{'helo'} = $1 if $line =~ / H=(.*?)(?= [A-Z]=)/;
                $data->{'total_outgoing'}++;
                $data->{'domain_responsibility'}{lc($from_domain)}++ if defined $from_domain;
                $data->{'mailbox_responsibility'}{lc($from)}++;
                for ($data->{'mail_ids'}{$mailid}{'who'}) {
                    last if /@/;
                    $data->{'hourly_volume'}{$_}{substr($line,0,13)}++;
                    $data->{'responsibility'}{$_}++;
                    $data->{'owner_responsibility'}{$data->{'user2owner'}{$_}}++
                        if exists $data->{'user2owner'}{$_}
                        && $data->{'user2owner'}{$_} ne 'root'
                }
            }
        }
        elsif (substr($line,37,2) eq '**') {
            if ($line =~ m,Domain (\S+) has exceeded the max emails per hour,) {
                $data->{'discarded_users'}{$data->{'domain2user'}{$1}}++;
                $data->{'mail_ids'}{$mailid}{'500_discarded'}++;
                $data->{'total_discarded'}++;
            }
        }
    }
}

sub analyze_queued_mail_data {
    for my $email (values %{$data->{'mail_ids'}}) {
        next unless $email->{'in_queue'};
        $data->{'script'}{$email->{'script'}}++ if exists $email->{'script'};
        for (qw(source auth_id ident auth_sender sender sender_domain)) {
            next if $_ eq 'sender' && $email->{sender} eq 'mailer-daemon';
            next if $_ eq 'ident' && $email->{ident} eq 'mailnull';
            next if $_ eq 'source' && $email->{source} =~ /^gateway\d+\.websitewelcome\.com$/;
            $data->{'queue_top'}{$_}{$email->{$_}}++ if defined $email->{$_}
        }
        for my $field (qw(recipient_domains recipient_users)) {
            for (keys %{$email->{$field}}) {
                $data->{'queue_top'}{$field}{$_}++
            }
        }
    }
}

sub who {
    my ($email) = @_;
    my $who = '(unknown)';
    for (qw(ident auth_id auth_sender source sender)) {
        if (exists $email->{$_}) {
            $who = $email->{$_};
            last
        }
    }
    if ($who =~ /@(.*)/ and exists $data->{'domain2user'}{$1}) {
        $who = $data->{'domain2user'}{$1};
    }
    $who
}

# sending 200 emails each to 2 of 2 total addresses = OK
# sending 200 emails each to 2 of 400 total addresses = SUSPECT
# sending 200 emails each to 2 of 201 total addresses = OK (self CC)
# implemented: SUSP.NR1 suspect if total addresses / emails >= 1.20
sub analyze_num_recipients {
    my %suspects;
    my %emails;

    # add suspect: anything with more than one recipient
    for my $email (values %{$data->{'mail_ids'}}) {
        next unless $email->{'num_recipients'} > 1;
        $suspects{$email->{'who'}}{$_} = 1 for @{$email->{'recipients'}};
        $emails{$email->{'who'}}++;
    }

    # confirm suspect: anything passing SUSP.NR1
    for (keys %suspects) {
        my $r = keys(%{$suspects{$_}}) / $emails{$_};
        if ($r >= 1.2) {
            $data->{'suspects'}{'num_recipients'}{$_} = {
                addresses => scalar(keys(%{$suspects{$_}})),
                emails => $emails{$_},
                ratio => $r
            };
        }
    }
}

1;
} # end module SpamReport::Exim
BEGIN {
$INC{'SpamReport/Exim.pm'} = '/dev/null';
}

BEGIN {
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
BEGIN {
$INC{'SpamReport/Exim/DB.pm'} = '/dev/null';
}

BEGIN {
package SpamReport::Maillog;
use SpamReport::Data;
use SpamReport::GeoIP;

use common::sense;

use vars qw/$VERSION/;
$VERSION = '2016022601';

use Time::Local;
use File::Basename;
use Regexp::Common qw/ Maillog /;
use Socket qw(inet_aton inet_ntoa);
use Sys::Hostname::Long qw(hostname_long);

my $hostname = hostname_long();
my $main_ip = inet_ntoa(scalar gethostbyname($hostname || 'localhost'));

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
} # end module SpamReport::Maillog
BEGIN {
$INC{'SpamReport/Maillog.pm'} = '/dev/null';
}

{ # begin main package
package SpamReport;

use SpamReport::Data;
use SpamReport::ANSIColor;
use SpamReport::GeoIP;
use SpamReport::Tracking::Scripts;
use SpamReport::Tracking::Suspensions;
use SpamReport::Tracking::Performance;
use Regexp::Common qw(SpamReport Exim Maillog);
use SpamReport::Annotate;
use SpamReport::Output;
use File::Nonblock;
use SpamReport::Cpanel;
use SpamReport::Exim;
use SpamReport::Exim::DB;
use SpamReport::Maillog;

use common::sense;
use 5.008_008; use v5.8.8;

use vars qw/$VERSION/;
$VERSION = '2016022601';

use Time::Local;
use Time::localtime;
use POSIX qw(strftime);
use Date::Parse;

use Getopt::Long qw(GetOptions HelpMessage VersionMessage);
use Pod::Usage;

use File::Basename;
use IO::Handle;

use Socket qw(inet_aton inet_ntoa);
use Sys::Hostname::Long qw(hostname_long);

use Regexp::Common qw/Exim Maillog SpamReport/;
use YAML::Syck qw(DumpFile);  # only for --dump

#use base qw(
#    SpamReport::Output
#    SpamReport::Cpanel
#    SpamReport::Exim
#    SpamReport::Maillog
#    SpamReport::Exim::DB
#    File::Nonblock
#);

# Bypass using timelocal to calculate the timezone offset
my @time = CORE::localtime(time);
my $tz_offset = timegm(@time) - timelocal(@time);
my $now = strftime("%s", @time);
my @months = qw[Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec];
my %month_to_ord = map {$months[$_] => $_} (0 .. $#months);

my %OPTS = (
    'search_hours'  => 72,
    'start_time'    => 0,
    'end_time'      => scalar CORE::localtime($now),
    'time_override' => undef,
    'read_lines'    => 10000,
    'r_cutoff'      => 1.0,

    'report'        => 'summary',
    # other values: user, script, md5, logins, forwarders, helos, cachelist

    # summary categories
    'with_queue'    => 1,
    'with_scripts'  => 1,
    'with_mail'     => 1,
    'with_auth'     => 1,
    'with_forward'  => 1,

    # work categories
    'want_queue'    => 0,
    'want_maillog'  => 0,
    'want_eximlog'  => 0,
    'want_scripts'  => 0,
    'want_eximdb'   => 0,

    # operation modes
    'op'            => 'report',
    # other values: 'cron', 'update'
    
    # data modes
    'load'          => 'cron',
    # other values: 'cache', undef
    'save'          => 1,
);

my @SAVED_OPTS = qw(search_hours start_time end_time timespec);

my $hostname = hostname_long();
my $main_ip = inet_ntoa(scalar gethostbyname($hostname || 'localhost'));

my %factories;
my %sections;

sub check_options {
    Getopt::Long::Configure(qw(gnu_getopt auto_version auto_help));
    my $time_changed;
    my $tag_flag;
    my $result;
    my $ecpp;

    if (basename($0) =~ m/^ec|ecpp$/) {
        $ecpp = 1;
        $OPTS{'report'} = 'user';
        $OPTS{'load'} = 'cache';
        $OPTS{'full'} = 1;
        $OPTS{'hourly_report'} = 1;
        $result = GetOptions(
            'start|s=s'   => sub { $time_changed++; $OPTS{'start_time'} = $_[1]; },
            'end|e=s'     => sub { $time_changed++; $OPTS{'end_time'} = $_[1]; },
            'hours|h=i'   => sub { $time_changed++; $OPTS{'search_hours'} = $_[1]; },
#            'created|c=s' => sub { $OPTS{'report'} = 'acctls'; $OPTS{'email'} = $_[1]; },
            'reseller|r'  => \$OPTS{'reseller'},
            'help|?'      => sub { ec_usage() },
            'version'     => sub { VersionMessage(module_versions()) },
        );
        ec_usage() unless @ARGV == 1;
        $OPTS{'user'} = $ARGV[0];
    } else {
        $result = GetOptions(
            'start|s=s'   => sub { $time_changed++; $OPTS{'start_time'} = $_[1]; },
            'end|e=s'     => sub { $time_changed++; $OPTS{'end_time'} = $_[1]; },
            'hours|h=i'   => sub { $time_changed++; $OPTS{'search_hours'} = $_[1]; },
#            'created|c=s' => sub { $OPTS{'report'} = 'acctls'; $OPTS{'email'} = $_[1]; },
#            'time|t=s'    => \$OPTS{'timespec'},
            'override|o'  => \$OPTS{'time_override'},
            'read=i'      => \$OPTS{'read_lines'},
            'uncached'    => \$OPTS{'uncached'},  # experimental, undocumented
            'cutoff=i'    => \$OPTS{'r_cutoff'},  # experimental, undocumented

            'without|w=s' => \$OPTS{'without'},
            'full|f'      => \$OPTS{'full'},
            'user|u=s'    => sub { if ($OPTS{'report'} eq 'summary') { $OPTS{'report'} = 'user'; $OPTS{'load'} = 'cache' } $OPTS{'user'} = $_[1]; $OPTS{'full'} = 1 },
            'hourly'      => \$OPTS{'hourly_report'},
            'reseller|r'  => \$OPTS{'reseller'},

            'scripts'     => sub { $OPTS{'report'} = 'script'; $OPTS{'load'} = 'no' },
            'md5=s'       => sub { $OPTS{'report'} = 'md5'; $OPTS{'scriptmd5report'} = $_[1]; $OPTS{'load'} = 'no' },
            'logins'      => sub { $OPTS{'report'} = 'logins' },
            'helos'       => sub { $OPTS{'report'} = 'helos' },
            'forwarders'  => sub { $OPTS{'report'} = 'forwarders' },

            'load=s'      => sub { $OPTS{'load'} = 'cache'; SpamReport::Data::resolve($_[1]); $OPTS{'save'} = 0 },
            'loadcron=s'  => sub { $OPTS{'load'} = 'cron'; SpamReport::Data::resolvecron($_[1]); $OPTS{'save'} = 0 },
            'save'        => \$OPTS{'save'},  # undocumented
            'dump=s'      => \$OPTS{'dump'},
            'keep=i'      => \$SpamReport::Data::MAX_RETAINED,

            'tag=s'       => sub { $SpamReport::Data::logpath =~ s/(?=\.gz)/.$_[1]/;
                                   $SpamReport::Data::cronpath =~ s/(?=\.gz)/.$_[1]/;
                                   $tag_flag = 1; },
            'ls'          => sub { $OPTS{'report'} = 'cachels'; $OPTS{'load'} = 'no' },
            'cron'        => sub { $OPTS{'op'} = 'cron'; $OPTS{'load'} = undef },
            'update'      => sub { $OPTS{'op'} = 'update' },
            'latest'      => sub { $OPTS{'load'} = 'cache' },

            'help|?'      => sub { HelpMessage() },
            'man'         => sub { pod2usage(-exitval => 0, -verbose => 2) },
            'version'     => sub { VersionMessage(module_versions()) },
        );
    }

    # XXX: reports that don't work with cache currently
    if ($OPTS{'load'} eq 'cache' && $OPTS{'report'} eq 'forwarders') {
        $OPTS{'load'} = 'cron';
    }
    if ($time_changed && $ecpp) {
        warn "[WARNING] Non-default times requested.\n\n",
             "* ec uses daily and hourly cache to speed up normal usage.\n",
             "*\n",
             "* Using non-default times can slow it down by a factor of 60x or more.\n\n";
        $OPTS{'load'} = undef;
        SpamReport::Data::disable()
    }
    elsif ($OPTS{'op'} eq 'report' && $time_changed) {
        die "${RED}[FAULT] Non-default times requested without --override flag!$NULL\n",
             "\n",
             "* spamreport uses daily and hourly cache to speed up normal usage.\n",
             "*\n",
             "* Using non-default times can slow spamreport down by a factor of 60x or more.\n",
             "*\n",
             "* If you really mean to do this, pass the --override flag.\n",
             "*\n",
             "* (or c.f CREATING NONDEFAULT CACHE in spamreport --man)\n\n"
            unless $OPTS{'time_override'};
        $OPTS{'load'} = undef;
        SpamReport::Data::disable() unless $tag_flag;
    } elsif ($time_changed) {
        warn "${RED}[WARN] Saving over default cache with non-default time arguments (did you mean to use --tag?)$NULL\n"
            unless $tag_flag;
        $OPTS{'load'} = undef;
    }
    
    $OPTS{'want_queue'} = 1 if $OPTS{'op'} ne 'cron' && $OPTS{'with_queue'};
    $OPTS{'want_maillog'} = 1 if $OPTS{'op'} ne 'report' or $OPTS{'report'} eq 'logins';
    $OPTS{'want_eximlog'} = 1 unless $OPTS{'report'} eq 'md5'
                                  or $OPTS{'report'} eq 'logins';
    $OPTS{'want_scripts'} = 1 if $OPTS{'want_eximlog'} or $OPTS{'report'} eq 'md5';
    # eximdb: unused

    if ( $OPTS{'start_time'} && $OPTS{'start_time'} !~ m/^\d+$/ ) {
        $OPTS{'start_time'} = str2time($OPTS{'start_time'}) or die "Invalid start time";
    }

    if ( $OPTS{'end_time'} && $OPTS{'end_time'} !~ m/^\d+$/ ) {
        $OPTS{'end_time'} = str2time($OPTS{'end_time'}) or die "Invalid end time";
    }

    if ( $OPTS{'start_time'} && $OPTS{'end_time'} ) {

        ($OPTS{'start_time'}, $OPTS{'end_time'}) = ($OPTS{'end_time'}, $OPTS{'start_time'})
            if ( $OPTS{'start_time'} > $OPTS{'end_time'} );

    }

    # filesystem security, if we're putting dumps somewhere
    # 1. ensure that the directory exists (just a way of ensuring that the path is sensible)
    # 2. ensure that the directory is owned by root
    # 3. ensure that created files don't have group or other perms
    #    (and make them non-executable for root as well)
    for (defined($OPTS{'dump'}) ? $OPTS{'dump'} : ()) {
        my $d;
        if (-d $_) { $d = $_ }
        elsif (m,^(/.*)/[^/]+$, && -d $1) { $d = $1 }
        elsif ($_ !~ m,/,) { $d = '.' }
        else { die "Directory doesn't exist for --dump target: $_" }

        if (! -o $d) {
            die "--dump target must be owned by root: $d"
        }
    }
    umask 0177;
    mkdir "/opt/hgmods/logs/", 0700;

    $OPTS{'start_time'} = $OPTS{'end_time'} - ($OPTS{'search_hours'} * 3600) if ( ! $OPTS{'start_time'} );

    die "Invalid number of lines to read: " . $OPTS{'read_lines'} if ( $OPTS{'read_lines'} <= 0 );


    my (%dovecot, %exim);
    for (my $i = $OPTS{'end_time'}; $i >= $OPTS{'start_time'}; $i -= 3600 * 24) {
        $exim{POSIX::strftime("%F", CORE::localtime($i))}++;
        $dovecot{POSIX::strftime("%b %d", CORE::localtime($i))}++;
    }
    $OPTS{'dovecot_days'} = \%dovecot;
    $OPTS{'exim_days'} = \%exim;
    $OPTS{'exim_today'} = POSIX::strftime("%F", CORE::localtime());
    $OPTS{'dovecot_today'} = POSIX::strftime("%b %d", CORE::localtime());

    my (%dovecotpost, %eximpost);
    for (my $i = $OPTS{'end_time'} + 3600 * 24; $i < $OPTS{'end_time'} + 3600 * 24 * 4; $i += 3600 * 24) {
        $eximpost{POSIX::strftime("%F", CORE::localtime($i))}++;
        $dovecotpost{POSIX::strftime("%b %d", CORE::localtime($i))}++;
    }
    $OPTS{'dovecot_postdays'} = \%dovecotpost;
    $OPTS{'exim_postdays'} = \%eximpost;

    return $result;
}

sub parse_retries {

    my ($key, $value) = @_;

    # typedef struct {
    #   time_t time_stamp;
    #   /*************/
    #   time_t first_failed;    /* Time of first failure */
    #   time_t last_try;        /* Time of last try */
    #   time_t next_try;        /* Time of next try */
    #   BOOL   expired;         /* Retry time has expired */
    #   int    basic_errno;     /* Errno of last failure */
    #   int    more_errno;      /* Additional information */
    #   uschar text[1];         /* Text message for last failure */
    # } dbdata_retry;

    my ($type, $address, $log_data) = split /:/, $key;

    if ( $type eq 'R' and $log_data and not $log_data =~ m/H=cm\.websitewelcome\.com/ ) {
        my ($time_stamp, $first_failed, $last_try, $next_try, $expired, $basic_errno, $more_errno, $text)
            = unpack ('l x4 l x4 l x4 l x7 b1 i i Z*', $value);
        if ( not $expired and ($last_try >= $OPTS{'start_time'}) and ($last_try < $OPTS{'end_time'}) ) {
            $log_data =~ s/<|>//g;
            my ($mail_username, $mail_hostname) = split /@/, $log_data;
            $data->{'senders'}{$mail_username}{'retries'}++ if ( $mail_hostname eq $hostname );
        }
    }

    1;
}

sub parse_ratelimit {

    my ($key, $value) = @_;

    # typedef struct {
    #   time_t time_stamp;
    #   /*************/
    #   int    time_usec;       /* Fractional part of time, from gettimeofday() */
    #   double rate;            /* Smoothed sending rate at that time */
    # } dbdata_ratelimit;

    my (undef, $unit, $conn_ip) = split /\//, $key;

    my ($time_stamp, $time_usec, $rate) = unpack ('l x4 i x4 d', $value);
    $data->{'ip_addresses'}{$conn_ip}{'conn_rate'} = $rate
        if ($time_stamp >= $OPTS{'start_time'} and $time_stamp < $OPTS{'end_time'} );

    1;

}

my $hidesti = qr/$RE{'spam'}{'hi_destination'}/i;
sub parse_wait {
 
    my ($key, $value) = @_;

    # typedef struct {
    #   time_t time_stamp;
    #   /*************/
    #   int    count;           /* Count of message ids */
    #   int    sequence;        /* Sequence for continued records */
    #   uschar text[1];         /* One long character string */
    # } dbdata_wait;
    
    my ($host) = split /:/, $key;

    my ($time_stamp, $count, $sequence) = unpack ('l x4 i i', $value);
    my @mail_ids = unpack ("x[l] x4 x[i] x[i] (A16)$count", $value);

    if ($host =~ $hidesti) {
        $data->{'mail_ids'}{$_}{'send_delays'}++ for (@mail_ids);
        $data->{'dest_domains'}{$1}{'delays'}++ for (@mail_ids);
    }

    1;
}

sub show_progress {
    my ($file_handle, $new_text, $threshold, $increment) = @_;

    $new_text ||= File::Nonblock::progress_state($file_handle);
    $threshold ||= 1;
    $increment ||= 10;

    my $file_name = File::Nonblock::name($file_handle) or die "Non-open file handle";
    my $change = File::Nonblock::new_progress($file_handle, $threshold);
    my $cur_text = File::Nonblock::progress_state($file_handle);

    if ( $change
         or File::Nonblock::tell($file_handle) == 0
         or $cur_text ne $new_text ) {

        my $text = $cur_text eq $new_text ? $cur_text
                                          : File::Nonblock::set_progress_state($file_handle, $new_text);

        my $percentage = int(File::Nonblock::progress($file_handle) * 100);

        if ( -t STDOUT ) {
            print "\r\e[K\r$text $file_name: ($percentage%)";
        }
        else {
            if ( $percentage == 0 ) {
                print "$text $file_name: ";
            }
            elsif ( $cur_text ne $new_text ) {
                print " $text ";
            }

            if ( ($percentage % $increment ) + $change > $increment ) {
                $percentage = $percentage + $change - $increment;
                $change -= $increment;
            }

            if ( ( $percentage == 0) || ($percentage % $increment == 0) ) {
                print "$percentage%";
            }
            else {
                print "." x $change;
            }
        }
    }

    1;
}

sub get_next_lines {
    my ($log_fh, $year, $allow_year_dec) = @_;
    my $lines = File::Nonblock::read_lines($log_fh, $OPTS{'read_lines'});
    $lines && return ($year, $lines)
}

sub parse_exim_dbs {
    my %db_parsers = (
        'retry'            => \&parse_retries,
        'ratelimit'        => \&parse_ratelimit,
        'wait-remote_smtp' => \&parse_wait,
    );

    for my $db_name ( keys %db_parsers ) {
        SpamReport::Exim::DB::open($db_name);
        SpamReport::Exim::DB::read($db_name, $db_parsers{$db_name});
        SpamReport::Exim::DB::close($db_name);
    }

    1;
}

sub parse_exim_queue {
    SpamReport::Exim::parse_queued_mail_data($OPTS{'start_time'}, $OPTS{'end_time'});
}

sub parse_logs {
    my ($handler, @logs) = @_;
    if ($data->{'OPTS'}{'datelimit'} eq 'only today') {
        @logs = grep { -M $_ < 1 } @logs
    }

    for my $logfile (sort { -M $b <=> -M $a } @logs) {
        my $end_reached;
        my $mtime = (stat($logfile))[9];
        next if ( $mtime < $OPTS{'start_time'} );
        my $year = (CORE::localtime($mtime))[5];
        my $allow_year_dec = 1;
        my $lines;
        my $in_zone = [0];

        my $log = File::Nonblock::open($logfile, 8*1024) or die "Could not open $logfile";

        while (not File::Nonblock::eof($log)) {
            ($year, $lines) = get_next_lines($log, $year, $allow_year_dec) or $end_reached = 1;
            last if $end_reached;

            if ( File::Nonblock::tell($log) != 0 ) {
                show_progress($log, 'Reading')
            }

            $handler->($lines, $year, $OPTS{'end_time'}, $in_zone);

            $allow_year_dec = 0;
        }

        File::Nonblock::close($log);
        print "\n";

        last if $end_reached;
    }

    1;
}

sub parse_cpanel_logs {
    return if $data->{'OPTS'}{'datelimit'} eq 'not today';
    parse_logs(\&SpamReport::Cpanel::find_email_creation, glob '/usr/local/cpanel/logs/{access_log,archive/access_log-*.gz}');
}

sub parse_exim_logs {
    parse_logs(\&SpamReport::Exim::parse_exim_mainlog, glob '/var/log/exim_mainlog{,{-*,.?}.gz}');
}
sub parse_dovecot_logs {
    parse_logs(\&SpamReport::Maillog::find_dovecot_logins, glob '/var/log/maillog{,{-*,.?}.gz}');
}

sub setup_cpanel {
    my $new;

    my $userdomains_path = '/etc/userdomains';
    my $trueuserowners_path = '/etc/trueuserowners';
    my $valiases_path = '/etc/valiases';

    %factories = (
        'user:domain' => \&SpamReport::Cpanel::map_userdomains,
        'user:owner' => \&SpamReport::Cpanel::map_userowners,
        'alias:dest'  => \&SpamReport::Cpanel::map_valiases,
    );

    %{ $new } = map {

        my $data_path = $_ eq 'user:domain' ? $userdomains_path
                      : $_ eq 'user:owner'  ? $trueuserowners_path
                      : $_ eq 'alias:dest'  ? $valiases_path
                                            : die 'Unexpected error';

        my @map_names = split ':';
        my @map_data = $factories{$_}($data_path);

        my $map1 = $map_names[0] . '2' . $map_names[1];
        my $map2 = $map_names[1] . '2' . $map_names[0];

        ($map1 => $map_data[0], $map2 => $map_data[1]);

    } keys %factories;

    $data->{$_} = $new->{$_} for keys %$new;

    1;
}

sub user {
    my ($user) = @_;
    if (exists $data->{'domain2user'}{$user}) {
        print "Assuming you mean $data->{'domain2user'}{$user} by $user\n";
        $user = $data->{'domain2user'}{$user};
    }
    die "No such user: $user" unless getpwnam($user);
    $user
}

sub purge {
    my %users = map { ($_, 1) } @_;
    for (keys %{$data->{'mail_ids'}}) {
        if (exists $users{$data->{'mail_ids'}{$_}{'who'}}) {
            if ($data->{'mail_ids'}{$_}{'type'} eq 'bounce') {
                $data->{'total_bounce'}--;
                $data->{'filtered_bounce'}++;
            } else {
                $data->{'total_outgoing'}--;
                $data->{'filtered_outgoing'}++;
            }
            delete $data->{'mail_ids'}{$_};
        }
    }
    for (keys %users) {
        delete $data->{'responsibility'}{$_};
        delete $data->{'owner_responsibility'}{$_};
        delete $data->{'bounce_responsibility'}{$_};
        delete $data->{'bounce_owner_responsibility'}{$_};
    }
    for (keys %{$data->{'outscript'}}) {
        delete $data->{'outscript'}{$_} if m,^/[^/]+/([^/]+)/, && exists $users{$1}
    }
    for (keys %{$data->{'scriptdirs'}}) {
        delete $data->{'scriptdirs'}{$_} if m,^/[^/]+/([^/]+)/, && exists $users{$1}
    }
}

sub userfy_args {
    $OPTS{'without'} = [map { user($_) } split ' ', $OPTS{'without'}]
        if defined $OPTS{'without'};
    $OPTS{'user'} = user($OPTS{'user'})
        if $OPTS{'report'} eq 'user' && $OPTS{'user'} ne 'root';
}

sub main {
    my $loadedcron;

    STDOUT->autoflush(1);
    STDERR->autoflush(1);

    die "This script only supports cPanel at this time."
        unless -r '/etc/userdomains' && -d '/etc/valiases';
    check_options() or pod2usage(2);

    SpamReport::Tracking::Scripts::disable() unless $OPTS{'want_scripts'};
    SpamReport::Data::disable() if $OPTS{'uncached'};
    SpamReport::Tracking::Scripts::load();

    if ($OPTS{'load'} eq 'cron') {
        SpamReport::Data::loadcron();
        if (keys %$data) {
            $loadedcron = 1;
            $OPTS{$_} = $data->{'OPTS'}{$_} for @SAVED_OPTS;
        } else {
            warn "${RED}daily cache not not loaded! $SpamReport::Data::loadcronfail\n"
               . "This run will take much longer than normal$NULL\n"
        }
    }
    DumpFile($OPTS{'dump'}.".cron", $data) if $loadedcron && $OPTS{'dump'};

    $data->{'OPTS'} = \%OPTS;

    if ($OPTS{'op'} eq 'cron' or $OPTS{'op'} eq 'update') {
        SpamReport::Output::head_info(\%OPTS);
        setup_cpanel();
        if ($OPTS{'op'} eq 'cron' || !$loadedcron) {
            $OPTS{'datelimit'} = 'not today';
            parse_exim_dbs() if $OPTS{'want_eximdb'};
            parse_exim_logs() if $OPTS{'want_eximlog'};
            parse_dovecot_logs() if $OPTS{'want_maillog'};
        }
        if ($OPTS{'op'} eq 'update') {
            SpamReport::Data::savecron() if !$loadedcron && $OPTS{'save'};
            $OPTS{'datelimit'} = 'only today' if $loadedcron;
            parse_exim_dbs() if $OPTS{'want_eximdb'};
            parse_exim_logs() if $OPTS{'want_eximlog'};
            parse_exim_queue() if $OPTS{'want_queue'};
            parse_dovecot_logs() if $OPTS{'want_maillog'};
            DumpFile($OPTS{'dump'}.".scan", $data) if $OPTS{'dump'};
        }
        SpamReport::Cpanel::young_users();
        SpamReport::Tracking::Scripts::save() if $OPTS{'save'};
        SpamReport::Data::exitsavecron() if $OPTS{'op'} eq 'cron';
        SpamReport::Cpanel::offserver_forwarders();
        SpamReport::Data::save() if $OPTS{'save'};
        exit
    }

    # op: report


    my $cacheloaded;
    if ($OPTS{'load'} eq 'no') {
        # no need to load data
        SpamReport::Output::head_info($data->{'OPTS'});
        SpamReport::Tracking::Scripts::save() if $OPTS{'save'};
    } elsif ($OPTS{'load'} eq 'cache') {
        SpamReport::Data::load() && $cacheloaded++
    }

    if ($OPTS{'load'} eq 'cache' && $cacheloaded) {
        userfy_args();
        $OPTS{$_} = $data->{'OPTS'}{$_} for @SAVED_OPTS;
        $data->{'OPTS'} = \%OPTS;
        SpamReport::Output::head_info($data->{'OPTS'});
    } elsif ($OPTS{'load'} ne 'no') {
        if (!$cacheloaded) {
            "${RED}failed to load cache!  This run may take much longer than normal.$NULL\n";
        }
        SpamReport::Output::head_info($data->{'OPTS'});
        setup_cpanel();
        userfy_args();
        SpamReport::Cpanel::offserver_forwarders();
        $OPTS{'datelimit'} = 'only today' if $loadedcron;
        parse_exim_dbs() if $OPTS{'want_eximdb'};
        parse_exim_queue() if $OPTS{'want_queue'};
        parse_exim_logs() if $OPTS{'want_eximlog'};
        parse_dovecot_logs() if $OPTS{'want_maillog'};
        SpamReport::Data::save() if $OPTS{'save'} && !$cacheloaded
            && !(defined($OPTS{'user'}) or
                 defined($OPTS{'without'}));
        SpamReport::Tracking::Scripts::save() if $OPTS{'save'};
    }
    SpamReport::Tracking::Suspensions::load();
    SpamReport::GeoIP::init();

    my @to_purge;
    push @to_purge, @{$OPTS{'without'}} if $OPTS{'without'};
    push @to_purge, SpamReport::Tracking::Suspensions::ticketed_users() unless $OPTS{'full'};
    purge(@to_purge) if @to_purge;
    
    if ($OPTS{'report'} eq 'user') {
        my $isreseller = $OPTS{'reseller'} || $OPTS{'user'} eq 'root';
        SpamReport::Output::analyze_user_results($OPTS{'user'}, $isreseller);
        SpamReport::Output::print_user_results($OPTS{'user'}, $isreseller);
        exit;
    }

    if ($OPTS{'report'} eq 'acctls') {
        
        SpamReport::Output::email_search_results($OPTS{'email'});
        exit;
    }

    if ($OPTS{'report'} eq 'script') {
        SpamReport::Output::print_script_report();
        exit;
    }

    if ($OPTS{'report'} eq 'md5') {
        SpamReport::Output::print_script_info($OPTS{'scriptmd5report'});
        exit
    }

    if ($OPTS{'report'} eq 'logins') {
        SpamReport::Maillog::analyze_logins();
        SpamReport::Output::print_login_results(); 
        exit;
    }

    if ($OPTS{'report'} eq 'helos') {
        SpamReport::Output::analyze_helos();
        SpamReport::Output::print_helo_report();
        exit;
    }

    if ($OPTS{'report'} eq 'forwarders') {
        SpamReport::Cpanel::offserver_forwarders();
        SpamReport::Output::print_forwarder_abuse();
        exit;
    }

    if ($OPTS{'report'} eq 'cachels') {
        SpamReport::Output::cache_ls();
        exit;
    }

    die "Invalid \$OPTS{'report'} : $OPTS{'report'}"
        unless $OPTS{'report'} eq 'summary';

    SpamReport::Output::analyze_results(); 
    SpamReport::Output::print_results(); 
}

sub module_versions {
    my $output;
    for (qw(SpamReport::GeoIP
            SpamReport::Data
            SpamReport::Tracking::Scripts
            SpamReport::Tracking::Suspensions
            SpamReport::Tracking::Performance
            Regexp::Common::Exim
            Regexp::Common::Maillog
            Regexp::Common::SpamReport
            SpamReport::ANSIColor
            SpamReport::Annotate
            SpamReport::Output
            File::Nonblock
            SpamReport::Cpanel
            SpamReport::Exim
            SpamReport::Exim::DB
            SpamReport::Maillog
            SpamReport)) {
        my $v = ${$_."::VERSION"};
        if ($v =~ /^(\d{4}) (\d{2}) (\d{2}) (\d{2})$/x) {
            $v = $months[$2-1] . " $3, $1 rev. " . (0+$4)
        }
        $output .= "($v) $_\n"
    }
    $output
}

sub ec_usage {
    print <<USAGE;
ec(spamreport) - Version: $VERSION - Ryan Egesdahl and Julian Fondren

Default usage, generates a report for a user, using the latest spamreport cache
for the last three days of logs:

  # ec <username>
  # ec <domain>

Get a report of all users on the server:

  # ec root

Search across all users for a reseller:

  # ec -r <reseller username or domain>
  # ec --reseller <reseller username or domain>

---
The default uses cache and three days of logs and is very fast (even when slow,
it's still much faster than the alternatives) when this cache is available.
You can change the time range from the default, but

  1. the minimum resolution is one day.  If you ask for '2 hours', at 1AM this
     will get you all of yesterday's logs as well.  At 2:01 AM you'll only get two
     hours worth of logs.  At noon you'll get 12 hours worth of logs.

  2. cache is no longer used, and logs will have to actually be parsed!
---

Parse the last <hours> worth of logs:

  # ec -h <hours> <user or domain>
  # ec --hours=<hours> <user or domain>

Parse with a given start and end time:

  # ec --start '<start time>' --end '<end time>' <user or domain>

Produce this output:

  # ec --help

Produce version information:

  # ec --version

USAGE
    exit 1;
}

__PACKAGE__->main unless caller; # call main function unless we were included as a module

END {
    DumpFile($OPTS{'dump'}.".post", $data) if $OPTS{'dump'};
}

1;
} # end main package
BEGIN {
$INC{'SpamReport.pm'} = '/dev/null';
}

__END__

=head1 NAME

spamreport - Quickly report suspicious mail behavior on a server

=head1 SYNOPSIS

spamreport [--current] [--dbs] [-sehmn] [other long options...]

options:

    -s <time>   | --start=<time>
    -e <time>   | --end=<time>
    -h <hours>  | --hours=<hours>
        (default: 72 hours)
        (NB. spamreport has a minimum granularity of one calendar day)

    -u <user>   | --user=<user>         : report on a user, implies --latest
                | --hourly              : add emails/hour to --user output
    -r          | --reseller            : include user's resold accounts

                | --logins              : print login report
                | --forwarders          : print forwarder reporter
                | --scripts             : print scripts report
                | --md5 <md5sum>        : print details about a script md5sum
                | --helos               : print HELO report

    -w          | --without=<u1 u2 ..>  : remove users' email before reporting
    -f          | --full                : don't remove ticketed users' email

                | --cron                : gather crondata, save it, and exit
                | --update              : gather fulldata, save it, and exit
                | --latest              : use fulldata if present
                | --load=path/to/file   : load data from file
                | --keep=<number>       : preserve # of rotated logs
                | --tag=<tag>           : use tagged instead of default cache
                | --ls                  : show available cache files

                | --dump=path/to/file   : save (human-readable) YAML files to
                                          $path.cron  : --cron seeded data
                                          $path.scan  : pre-analysis data
                                          $path.post  : post-analysis data

                | --help
                | --man
                | --version

Usage:

    spamreport [--full]
    spamreport -u <user> [--hourly]
    spamreport -u <reseller> -r
    spamreport -u root

    spamreport --logins [-u <user>]
    spamreport --forwarders [--full] [-u <user>]
    spamreport --scripts [--full]
    spamreport --md5 <md5sum>
    spamreport --helos [--full] [-u <user>]

    spamreport --without "baduser boringuser checkeduser" [...]

    spamreport --cron     # update previous-days' cache (cache used by default)
    spamreport --update   # update today's cache (cache ignored by default)
    spamreport --latest   # use today's cache

Indicator key:

    ABC-12341234.http  | a ticket ID in an active abusetool suspension
    abuse:#            | user was abusetool'd # times in the last 60 days
    security:12h       | ~user/.security was modified $time ago
    discard:22.3%      | % of user's email that hit the 500/hr limit

    seen:              | first root history mention of user within last week
    (user age)         | user was added to cPanel <2 weeks ago
    stale:             | <10% of user's email was sent in last 24 hours
    recent:            | >80% of user's email was sent in last 24 hours

    fake_accts?        | >80% of email sent by underbar_accounts@domain.com
    bad_sender?        | >90% of email has a suspect domain or spam TLD
    bad_recipients?    | >90% of email intended for critical destinations
    cron?              | >90% of email has subjects suggesting crond mail
    script_comp?       | >90% of email sent by a script
    bots?              | >80% of email has subjects resembling CMS mail
                         e.g. Account Details for ...

    boxtrapper:        | >50% of email has subjects suggesting boxtrapper
  bob@domain.com(IPs)  | mailbox has more than 10 /16 IPs authenticating as it

=head1 CREATING NONDEFAULT CACHE

    The intent is that a once-daily cron will update daily cache, and that a
    once-hourly cron will update cache over the course of the day, and that
    most queries can make use the hourly cache to provide useful and timely
    information about the server's last few days.

    On a VPS or dedicated server, you won't have the cache to use.  On a shared
    server, you may to perform a series of historical queries -- f.e., get a
    general report about a week-long period a month ago, and then get a user
    report from that period.  To speed up multiple queries you can create the
    cache to use yourself.  So as to not confuse the next admin that comes
    along (and, potentially, to keep the data for further investigation), you
    should tag your cache.

    For example:

      # spamreport --start '14 Feb' --end '17 Feb' --update --tag bad

    This will read files twice, first to create the daily cache and then to
    create the hourly cache.  Subsequent usage:

      # spamreport --load .bad
      # spamreport --load .bad -u badguy
      # spamreport --load .bad -u root
      # spamreport --load .bad --without "good1 good2"
      # spamreport   # a normal run, not using this cache

      # spamreport --ls   # see available cache

=head1 EXPLORING ON YOUR OWN

    You can pass spamreport, with --dump, a path to store YAML dumps of most of
    its data at several stages of operation.  You can then load this YAML with a
    normal oneliner and perform your own ad-hoc analysis of it, or otherwise
    explore it in ways not anticipated by spamreport's options.

      # perl spamreport --latest --tag '14-17feb2016' --dump=yaml
      ...
      # ls yaml*
      yaml.post
  
      # perl spamreport --dump=dump
      ...
      # ls dump*
      dump.cron  dump.post
  
      # egrep '^[^ ]' dump.cron
      --- 
      bounce_owner_responsibility: 
      bounce_responsibility: 
      domain_responsibility: 
      hourly_volume: 
      logins: 
      mail_ids: 
      mailbox_responsibility: 
      outscript: 
      owner_responsibility: 
      responsibility: 
      scriptdirs: 
      total_bounce: 10755
      total_outgoing: 16286
      # egrep -c '^[^ ]' dump.post
      40

    FILE.post is saved right before spamreport halts, and contains the most
    information.  It can also include analysis performed on behalf of the flags
    given along with the --dump flag.

      # perl -MYAML::Syck=LoadFile -le '$email = LoadFile("dump.post")->{"mail_ids"}; print $_->{"subject"} for values %$email'|grep -i paypal|sort|uniq -c|sort -nr|head
         8000 [Paypal-lnc] - Account Has Closed !
           15 [Team Paypal] : Your Account has limited
           12 [Paypal-lnc] : Account Has Closed !
            5 [Paypal-lnc] : Update Your Account !
            4 [Paypal-lnc] - Account Has Limeted !
            1 Paypal - Account Has Limeted !
      # perl -MYAML::Syck=LoadFile -le 'print join " " => sort keys %{LoadFile("dump.post")->{'young_users'}}'
ab7029 ab7266 adeola72 bodynas cameranclick cjzgproducciones done donex dpianes effacorg emege fassad75 ff ff1 ff2 ff3 ff4 ff5 ff6 fitter handhcom insidenwa jeune jmdproduction kamaracafe kcnasmedia lim lnc matrizbiotech maynaronline modoc nawboraleigh passinglane peakworx polygraphsa prestigetoy producershybrids prologues qashif rangpurstore rdnyc salahox santibibiloni scagrisolutions scamps seand secutronca shakespeares shivpuri speedkills uysys vfiber

=head1 FILES

    /opt/hgmods/logs/spamreportcron.dat  (and .1, .2, ...)

        Storable cache of data drawn from prior calendar days' email logs.
    
    /opt/hgmods/logs/spamreport.dat      (and .1, .2, ...)

        Storable cache of pre-analysis data drawn from prior runs.

    /opt/hgmods/logs/spamscripts.dat

        YAML script tracking data.

        "md5sum" -> "ips" -> (ips -> # hits by IP against md5sum)
                    "paths" -> (script paths -> # hits against path)

    /opt/hgmods/logs/spamperformance.log

        Text log of spamreport performance data.

        $date + $runtime secs : $email tracked emails : @ARGV

=head1 MODULES

=head2 package SpamReport;

=head3 check_options

    Argument handling.  Most flags result in modifications to %OPTS hash, which
    is duplicated in $data->{'OPTS'}, which is what every other package uses
    instead of %SpamReport::OPTS directly.

    Argument sanity checking, "x implies y", and date calculations are in this
    subroutine as well.

=head3 setup_cpanel

    Populate %data with cPanel information, such as user ownership & domain
    ownership.

=head3 main

    Toplevel function.  This governs cache loading and saving (now how this is
    done (that's in SpamReport::Data) but when it should be done) and fires off
    analysis and reporting functions as required by the current run.

=head2 package SpamReport::Output;

    Primary output and reporting module.  Of program output, only warnings,
    errors, progress updates, and ::Data loading messages are elsewhere.

=head2 package File::Nonblock;

    Reads log files in batches of lines, compressed or otherwise, with support
    for accurate progress indicators.

