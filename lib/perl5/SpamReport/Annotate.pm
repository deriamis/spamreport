package SpamReport::Annotate;
use common::sense;
use SpamReport::Data;

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
