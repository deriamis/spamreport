package SpamReport::Tracking::Scripts;
use YAML::Syck qw(DumpFile LoadFile);
use vars qw($VERSION);
use File::Which qw ( which );
use Time::Local;
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
