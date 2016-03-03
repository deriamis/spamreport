package SpamReport::Output;

use common::sense;
use SpamReport::Data;

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
