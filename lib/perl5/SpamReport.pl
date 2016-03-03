package SpamReport;
use SpamReport::Data;
use SpamReport::ANSIColor;

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

use base qw(
    SpamReport::Output
    SpamReport::Cpanel
    SpamReport::Exim
    SpamReport::Maillog
    SpamReport::Exim::DB
    File::Nonblock
);

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

END {
    DumpFile($OPTS{'dump'}.".post", $data) if $OPTS{'dump'};
}

my @SAVED_OPTS = qw(search_hours start_time end_time timespec);

my $hostname = hostname_long();
my $main_ip = inet_ntoa(scalar gethostbyname($hostname || 'localhost'));

my %factories;
my %sections;

sub run_ecpp {
    Getopt::Long::Configure(qw(gnu_getopt auto_version auto_help));
    my $result;
    my $time_changed;

    $OPTS{'report'} = 'user';
    $OPTS{'load'} = 'cache';
    $OPTS{'user'} = $ARGV[0];
    $OPTS{'full'} = 1;
    $result = GetOptions(
        'start|s=s'   => sub { $time_changed++; $OPTS{'start_time'} = $_[1]; },
        'end|e=s'     => sub { $time_changed++; $OPTS{'end_time'} = $_[1]; },
        'hours|h=i'   => sub { $time_changed++; $OPTS{'search_hours'} = $_[1]; },
#        'created|c=s' => sub { $OPTS{'report'} = 'acctls'; $OPTS{'email'} = $_[1]; },
        'reseller|r'  => \$OPTS{'reseller'},
        'help|?'      => sub { HelpMessage() },
        'version'     => sub { VersionMessage(module_versions()) },
    );

    HelpMessage() if (not defined ${OPTS}{'user'});

    return $result;
}

sub check_options {
    Getopt::Long::Configure(qw(gnu_getopt auto_version auto_help));
    my $time_changed;
    my $tag_flag;

    return run_ecpp() if (basename($0) =~ m/^ec|ecpp$/);

    my $result = GetOptions(
        'start|s=s'   => sub { $time_changed++; $OPTS{'start_time'} = $_[1]; },
        'end|e=s'     => sub { $time_changed++; $OPTS{'end_time'} = $_[1]; },
        'hours|h=i'   => sub { $time_changed++; $OPTS{'search_hours'} = $_[1]; },
#        'created|c=s' => sub { $OPTS{'report'} = 'acctls'; $OPTS{'email'} = $_[1]; },
#        'time|t=s'    => \$OPTS{'timespec'},
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

        'tag=s'       => sub { $SpamReport::Data::logpath .= ".$_[1]";
                               $SpamReport::Data::cronpath .= ".$_[1]";
                               $tag_flag = 1; },
        'ls'          => sub { $OPTS{'report'} = 'cachels'; $OPTS{'load'} = 'no' },
        'cron'        => sub { $OPTS{'op'} = 'cron'; $OPTS{'load'} = undef },
        'update'      => sub { $OPTS{'op'} = 'update' },
        'latest'      => sub { $OPTS{'load'} = 'cache' },

        'help|?'      => sub { HelpMessage() },
        'man'         => sub { pod2usage(-exitval => 0, -verbose => 2) },
        'version'     => sub { VersionMessage(module_versions()) },
    );

    # XXX: reports that don't work with cache currently
    if ($OPTS{'load'} eq 'cache' && $OPTS{'report'} eq 'forwarders') {
        $OPTS{'load'} = 'cron';
    }
    if ($OPTS{'op'} eq 'report' && $time_changed) {
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
        $OPTS{$_} = $data->{'OPTS'}{$_} for @SAVED_OPTS;
        if (keys %$data) {
            $loadedcron = 1;
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


    if ($OPTS{'load'} eq 'no') {
        # no need to load data
        SpamReport::Output::head_info($data->{'OPTS'});
        SpamReport::Tracking::Scripts::save() if $OPTS{'save'};
    } elsif ($OPTS{'load'} eq 'cache') {
        SpamReport::Data::load();
        userfy_args();
        $OPTS{$_} = $data->{'OPTS'}{$_} for @SAVED_OPTS;
        $data->{'OPTS'} = \%OPTS;
        SpamReport::Output::head_info($data->{'OPTS'});
    } else {
        SpamReport::Output::head_info($data->{'OPTS'});
        setup_cpanel();
        userfy_args();
        SpamReport::Cpanel::offserver_forwarders();
        $OPTS{'datelimit'} = 'only today' if $loadedcron;
        parse_exim_dbs() if $OPTS{'want_eximdb'};
        parse_exim_queue() if $OPTS{'want_queue'};
        parse_exim_logs() if $OPTS{'want_eximlog'};
        parse_dovecot_logs() if $OPTS{'want_maillog'};
        SpamReport::Data::save() if $OPTS{'save'} && !($OPTS{'load'} eq 'cache'
            or defined($OPTS{'user'})
            or defined($OPTS{'without'}));
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

__PACKAGE__->main unless caller; # call main function unless we were included as a module

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

