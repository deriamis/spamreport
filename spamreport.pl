#!/usr/bin/perl

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
package SpamReport::Output;

use common::sense;

use vars qw/$VERSION/;
$VERSION = '2015122201';

use Time::Local;
use List::Util qw(shuffle);

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

SpamReport.pl - Report suspicious mail activity
Written By: Ryan Egesdahl

Running: $sections

Searching $hours hours from [$start_time] to [$end_time] ...

END_INFO
}

sub email_search_results {
    my ($data) = @_;

    if ( exists $data->{'logins'} and scalar keys %{ $data->{'logins'} } > 0 ) {
        print "\nFound creation time(s) for:\n";
        print join "\n    ", keys %{ $data->{'logins'} };

        print "\n\nInformation:\n";
        map {
            print "    Login:        $_\n";
            print '    Created on:   ' . localtime($data->{'logins'}{$_}{'created_on'}) . "\n";
            print '    Created by:   ' . $data->{'logins'}{$_}{'created_by'} . "\n";
            print '    Created from: ' . $data->{'logins'}{$_}{'created_from'} . "\n\n";
        } keys %{ $data->{'logins'} };
    }
    else {
        print "\nNot found.\n";
    }
}

sub analyze_results {
    my ($data) = @_;

    SpamReport::Exim::analyze_queued_mail_data($data);
    SpamReport::Exim::analyze_num_recipients($data);
    analyze_mailboxes($data);
    SpamReport::Maillog::analyze_logins($data);

    1;
}

sub print_results {
    my ($data) = @_;

    print_queue_results($data) if exists $data->{'queue_top'};
    print_recipient_results($data) if exists $data->{'suspects'}{'num_recipients'};
    print_script_results($data);
    print_responsibility_results($data) if $data->{'responsibility'};
    print_login_results($data) if exists $data->{'suspects'}{'logins'};

    1;
}

sub analyze_mailboxes {
    my ($data) = @_;
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

sub widths {
    my ($h, $total) = (shift, shift);
    my @width = (0, 0);
    for (@_) {
        $width[0] = length($h->{$_}) if $h->{$_} > $width[0];
        $width[1] = length(sprintf "%.1f", 100*$h->{$_}/$total) if length(sprintf "%.1f", $h->{$_}) > $width[1]
    }
    @width
}

sub percent_report {
    my ($h, $total, $limit, $title) = @_;
    return unless $total;
    my @list = sort { $h->{$a} <=> $h->{$b} } grep { $h->{$_} / $total > $limit } keys %$h;
    my @width = (0, 0);
    for (@list) {
        $width[0] = length($h->{$_}) if $h->{$_} > $width[0];
        $width[1] = length(sprintf "%.1f", 100*$h->{$_}/$total) if length(sprintf "%.1f", $h->{$_}) > $width[1]
    }

    print "\nResponsibility for @{[commify($total)]} $title\n";
    for (reverse @list) {
        printf "%$width[0]d %$width[1].1f%% $_\n", $h->{$_}, 100*$h->{$_}/$total
    }
}

sub print_responsibility_results {
    my ($data) = @_;
    my ($emails, $bounces) = (0, 0);
    for (values %{$data->{'mail_ids'}}) {
        next if $_->{'in_queue'};
        if ($_->{'type'} eq 'bounce') {
            $bounces++;
        } else {
            $emails++;
        }
    }
    my $cutoff = $data->{'OPTS'}{'r_cutoff'} / 100;

    percent_report($data->{'responsibility'}, $emails, $cutoff, "outgoing emails");
    percent_report($data->{'bounce_responsibility'}, $bounces, $cutoff, "bouncebacks");
}

sub print_recipient_results {
    my ($data) = @_;
    my @widths = (0, 0);
    for (values %{$data->{'suspects'}{'num_recipients'}}) {
        my ($em, $ad) = (length($_->{'emails'}), length($_->{'addresses'}));
        $widths[0] = $em if $em > $widths[0];
        $widths[1] = $ad if $ad > $widths[1];
    }
    
    my %h = %{$data->{'suspects'}{'num_recipients'}};
    for (reverse sort { $h{$a}->{ratio} <=> $h{$b}->{ratio} } keys %h) {
        printf "%$widths[0]d %$widths[1]d %.4f num_recipients: $_\n",
            $h{$_}->{'emails'}, $h{$_}->{'addresses'}, $h{$_}->{'ratio'};
    }
}

sub scriptlimit {
    my ($h, $total, $per) = @_;
    my @r = grep { $h->{$_}/$total > $per } keys %$h;
    map { [$_, $h->{$_}, $total] } sort { $h->{$a} <=> $h->{$b} } grep { defined $_ } @r[0..4]
}

sub print_script_results {
    my ($data) = @_;
    my $scriptdirs = 0; $scriptdirs += $data->{'scriptdirs'}{$_} for keys %{$data->{'scriptdirs'}};
    my $script = 0; $script += $data->{'script'}{$_} for keys %{$data->{'script'}};
    my @r = (scriptlimit($data->{'scriptdirs'}, $scriptdirs, 0.1),
             scriptlimit($data->{'script'}, $script, 0.1));
    my @width = (0, 0);
    for (@r) {
        my $frac = length(sprintf "%.1f", 100*$_->[1]/$_->[2]);
        $width[0] = length($_->[1]) if length($_->[1]) > $width[0];
        $width[1] = $frac if $frac > $width[1]
    }

    print "\nResponsibility for @{[commify($scriptdirs)]} script dirs and @{[commify($script)]} scripts\n";
    for (reverse @r) {
        printf "%$width[0]d %$width[1].1f%% $_->[0]\n", $_->[1], 100*$_->[1]/$_->[2]
    }
    #for (sort { $data->{'script'}{$a} <=> $data->{'script'}{$b} } keys %{$data->{'script'}}) {
    #    print "$data->{'script'}{$_} $_\n"
    #}
    #for (sort { $data->{'script_ip'}{$a} <=> $data->{'script'}{$b} } keys %{$data->{'script_ip'}}) {
    #    print "$data->{'script_ip'}{$_} $_\n"
    #}
}

sub print_login_results {
    my ($data) = @_;
    my @width = (0, 0);
    my %h = %{$data->{'suspects'}{'logins'}};
    for (values %h) {
        my ($lo, $pr) = (length($_->{'total_logins'}), length(scalar(keys %{$_->{'logins_from'}})));
        $width[0] = $lo if $width[0] < $lo;
        $width[1] = $pr if $width[1] < $pr;
    }
    for my $login (reverse sort { $h{$a}{'total_logins'} <=> $h{$b}{'total_logins'} } keys %h) {
        my @ips = sort { $h{$login}{'logins_from'}{$b} <=> $h{$login}{'logins_from'}{$a} } keys %{$h{$login}{'logins_from'}};
        my @counts = map { $h{$login}{'logins_from'}{$_} } @ips;
        printf "%$width[0]d %$width[1]d $login   %s(%d) %s(%d) %s(%d)\n",
            $h{$login}{'total_logins'}, scalar(keys %{$h{$login}{'logins_from'}}),
            color(35, $ips[0]), $counts[0],
            color(33, $ips[1]), $counts[1],
            color(36, $ips[2]), $counts[2]
    }
}

sub print_queue_results {
    my ($data) = @_;
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

sub analyze_user_results {
    my ($data, $user) = @_;
    my ($sent, $bounce, $queued, $boxtrapper) = (0, 0, 0);
    my %sent;
    my %bounce;
    my %sent_as;
    my %ips;
    my %cwd;
    my %script;
    my %recip;
    my %subject;

    for my $email (values %{$data->{'mail_ids'}}) {
        if ($email->{'type'} eq 'bounce' && exists $email->{'recipient_users'}{$user}) {
            $bounce++;
            $bounce{$email->{'recipients'}->[0]}++;
            $queued++ if $email->{'in_queue'};
        }
        elsif ($email->{'type'} eq 'bounce' && exists $email->{'source'}{$user}) {
            $bounce++;
            $bounce{$email->{'source'}}++;
            $queued++ if $email->{'in_queue'};
        }
        elsif ($email->{'who'} eq $user) {
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
            for (keys %{$email->{'script'}}) {
                $script{$_}++
            }
            for (@{$email->{'recipients'}}) {
                $recip{$_}++
            }
            if (exists $email->{'subject'}) {
                $subject{$email->{'subject'}}++
            }
        }
    }
    for (keys %{$data->{'scriptdirs'}}) {
        next unless m,^/[^/]+/$user/,;
        $cwd{$_} += $data->{'scriptdirs'}{$_}
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
    (join "\n",
        map { "$_: $h->{$_}" }
        grep { defined $_ }
        (sort { $h->{$b} <=> $h->{$a} } keys %$h)[0..14])
    . remainder($h, $title)
}

sub topsubjects {
    my ($h) = @_;
    my $width = 0;
    for (values %$h) { $width = length($_) if $width < length($_) }
    (join "\n",
        map { sprintf "%${width}d $_", $h->{$_} }
        grep { defined $_ }
        (sort { $h->{$b} <=> $h->{$a} } keys %$h)[0..14])
}

sub remainder {
    my ($h, $title) = @_;
    my $rest = keys(%$h) - 15;
    return if $rest < 1;
    return "\n\nThere were @{[commify($rest)]} additional $title trimmed."
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
    return unless [values(%{$u->{'script'}})]->[0];
    return <<BOX
PHP Scripts:
------------
@{[sample($u->{'script'}, "PHP scripts")]}
BOX
}

sub print_user_results {
    my ($data, $user) = @_;
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

----------------------------------------

User sent approximately @{[commify($u->{'sent'})]} messages to @{[commify($u->{'recipients'})]} unique recipients.
There were @{[commify($u->{'bounce'})]} bounces on @{[commify($u->{'bounce_addresses'})]} unique addresses, @{[sprintf "%.2f%%", 100*$u->{'bounce'}/$total]} of the emails.

@{[boxtrapper($u, $total)]}Email addresses sent from:
--------------------------
@{[sample(\%sent_as, "sender addresses")]}

Logins used to send mail:
-------------------------
@{[sample($u->{'sent_accounts'}, "logins")]}

Current working directories:
----------------------------
@{[sample($u->{'cwd'}, "working directories")]}

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

Total number of discrete subjects: @{[commify($u->{'subject'})]}

Emails found in queue:
----------------------
User: @{[commify($u->{'queued'})]}, Total: @{[commify($data->{'total_queue'})]}

This user was responsible for @{[sprintf "%.2f%%", 100*($u->{'sent'}+$u->{'bounce'})/(scalar(keys %{$data->{'mail_ids'}}))]} of the emails found.


REPORT
}

sub top {
    my ($type, $h) = @_;
    map { [$h->{$_}, "$type: $_"] } keys %$h
}

{
    my $colors = !exists($ENV{nocolors}) && -t \*STDOUT;
    my %color = (
        green => 32,
        cyan => 36,
        red => 31,
        yellow => 33,
        magenta => "35;1",
    );

    my %fieldcolors = (
        source => $color{yellow},
        auth_id => $color{red},
        ident => $color{yellow},
        auth_sender => $color{red},
        sender_domain => $color{green},
        sender => $color{green},
        recipient_domains => $color{cyan},
        recipient_users => $color{cyan},
    );

    sub fieldcolor {
        my ($field) = @_;
        return $field unless exists $fieldcolors{$field};
        "\e[$fieldcolors{$field}m$field\e[0m"
    }
    sub color { "\e[$_[0]m$_[1]\e[0m" }
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
$VERSION = '2015122201';

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
$VERSION = '2015122201';

use Time::Local;
use Regexp::Common qw( SpamReport );
use File::Nonblock;

sub young_users {
    my ($data) = @_;
    my $time = time();
    for my $user (keys %{$data->{'user2domain'}}) {
        next if $user eq 'nobody';
        open my $f, '<', "/var/cpanel/users/$user"
            or do { warn "Unable to open /var/cpanel/users/$user : $!"; next };
        while ($_ = <$f>) {
            if (/^STARTDATE=(\d+)/ && ($time - $1) > (30 * 3600*24)) {
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

sub find_email_creation {
    my ($lines, $end_time, $data_ref, @search_list) = @_;
    for my $line ( @{ $lines } ) {
            
        if ( $line =~ m/$RE{'cpanel'}{'addpop'}/ ) {

            my %vars = map { split /=/ } split /&/, $4;
            my $login = $vars{'email'} . '@' . $vars{'domain'};

            next if ( scalar @search_list and not grep { $_ eq $login } @search_list );

            my $ipaddr = $1;
            my $username = $2;
            my $timestamp = 0;

            if ( $3 =~ m/$RE{'apache'}{'timestamp'}/ ) {
                $timestamp = timegm($6, $5, $4, $2, $1 - 1, $3 - 1900) - ($7 * 36);
            }

            last if ( $timestamp > $end_time );

            $data_ref->{'logins'}{$login}{'created_from'} = $ipaddr;
            $data_ref->{'logins'}{$login}{'created_by'} = $username;
            $data_ref->{'logins'}{$login}{'created_on'} = $timestamp;
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

            if ( $lines->[$n] =~ m/$RE{'cpanel'}{'addpop'}/ ) {

                if ( $3 ne $last_timestamp and $3 =~ m/$RE{'cpanel'}{'addpop'}/ ) {
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

use vars qw/$VERSION/;
$VERSION = '2015122201';

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
    my ($max_queue) = @_;
    my $queue_dir = '/var/spool/exim/input';
    my @headers;
    opendir my $d1, $queue_dir or die "Unable to open $queue_dir : $!";
    QUEUES: for my $subdir (readdir($d1)) {
        next if $subdir =~ /^\./;
        opendir my $d2, "$queue_dir/$subdir" or next;
        for (readdir($d2)) {
            if (/-H$/) {
                push @headers, "$queue_dir/$subdir/$_";
                last QUEUES if $max_queue && @headers >= $max_queue;
            }
        }
        closedir $d2;
    }
    closedir $d1;
    @headers
}

sub parse_queued_mail_data {
    my ($start_time, $end_time, $max_queue, $data_ref) = @_;

    my @new_mail = email_header_files($max_queue);
    for my $i (0..$#new_mail) {
        last if $max_queue && $i >= $max_queue;
    
        my $line_no = 0;
        my $tree_start = 0;
        my $eod = 0;
        my $num_recipients = 0;
        my @recipients;
        my ($mail_id) = $new_mail[$i] =~ m{/([^/]+)-H};
        my $new_email;

        # this rigamorale avoids: readline() on closed filehandle $fh at spamreport.pl...
        my @lines;
        eval {
                open my $fh, '<', $new_mail[$i];
                @lines = <$fh>;
                close $fh;
        }; next if $@;

        unless (exists $data_ref->{'mail_ids'}{$mail_id}) {
            $new_email = 1;
        }
        %{$data_ref->{'mail_ids'}{$mail_id}} = map {
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

        if (exists $data_ref->{'mail_ids'}{$mail_id}{'boxtrapper'}) {
            # we don't care about boxtrapper emails
            $data_ref->{'boxtrapper_queue'}++;
            delete $data_ref->{'mail_ids'}{$mail_id};
            next;
        }

        my $h_ref = $data_ref->{'mail_ids'}{$mail_id};
        my ($type, $source) = $h_ref->{'sender'} eq 'mailer-daemon'   ? ('bounce', $h_ref->{'helo_name'})
                            : exists $h_ref->{'local'}                ? ('local', $h_ref->{'ident'})
                            : $h_ref->{'host_auth'} =~ m/^dovecot_.*/ ? ('login', $h_ref->{'auth_id'})
                                                                      : ('relay', $h_ref->{'helo_name'});

        my $state = $h_ref->{'deliver_firsttime'} ? 'queued'
                  : $h_ref->{'frozen'}            ? 'frozen'
                                                  : 'thawed';

        $h_ref->{'type'} = $type;
        $h_ref->{'source'} = $source;
        $h_ref->{'state'} = $state;
        $h_ref->{'location'} = 'queue';
    
        ($h_ref->{'sender_domain'}) = $h_ref->{'sender'} =~ m/@(.*)$/;

        if ($h_ref->{'type'} ne 'bounce' && exists($data_ref->{'domain2user'}{lc($h_ref->{'sender_domain'})})) {
            # not a bounce and for a local domain?  it may be an issue but we don't care here
            $data_ref->{'local_queue'}++;
            delete $data_ref->{'mail_ids'}{$mail_id};
            next;
        }

        for (@{$h_ref->{'recipients'}}) {
            if ( $_ =~ m/@(.*)$/ ) {
                $data_ref->{'recipient_domains'}{$1}++;
                if (exists $data_ref->{'domain2user'}{$1}) {
                    $h_ref->{'recipient_users'}{$data_ref->{'domain2user'}{$1}}++
                }
            }
        }
    
        $h_ref->{'who'} = who($data_ref, $h_ref);
        $data_ref->{'responsibility'}{$h_ref->{'who'}}++ if $new_email and $h_ref->{'who'} !~ /@/;
        $h_ref->{'in_queue'} = 1;
        $data_ref->{'total_queue'}++;
    }
}

sub parse_exim_mainlog {
    my ($lines, $year, $end_time, $data_ref, $in_zone) = @_;
    my @lines = @$lines;
    my %days = %{$data_ref->{'OPTS'}{'exim_days'}};
    if ($data_ref->{'OPTS'}{'datelimit'} eq 'not today') {
        delete $days{$data_ref->{'OPTS'}{'exim_today'}};
    }
    elsif ($data_ref->{'OPTS'}{'datelimit'} eq 'only today') {
        %days = ($data_ref->{'OPTS'}{'exim_today'} => 1);
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

        if ( substr($line,20,4) eq 'cwd=' && $line =~ $RE{'exim'}{'info'}{'script'} ) {
            $data_ref->{'scriptdirs'}{$1}++;
            next
        }
        my $mailid = substr($line,20,16);
        
        if (substr($line,37,5) eq '<= <>') {
            $line =~ s/T=".*?(?<!\\)" //;
            next unless $line =~ /.*for (.*)$/;  # .* causes it to backtrack from the right
            my @to = split / /, $1;
            $line =~ / S=(\S+)/; for my $script ($1) {
                if (defined $script && $script !~ /@/ && $script =~ /\D/) {
                    $data_ref->{'mail_ids'}{$mailid}{'script'} = $script;
                    $data_ref->{'script'}{$script}++;
                }
            }
            $data_ref->{'mail_ids'}{$mailid}{'recipients'} = \@to;
            if (@to == 1 && $to[0] =~ /\@(\S+)/ and exists $data_ref->{'domain2user'}{$1}) {
                my $user = $data_ref->{'domain2user'}{$1};
                $data_ref->{'domain_responsibility'}{$1}++;
                $data_ref->{'mailbox_responsibility'}{$to[0]}++;
                $data_ref->{'bounce_responsibility'}{$user}++;
                $data_ref->{'mail_ids'}{$mailid}{'recipient_users'}{$user}++;
                $data_ref->{'mail_ids'}{$mailid}{'who'} = $user;
            }
            $data_ref->{'mail_ids'}{$mailid}{'type'} = 'bounce';
        }
        elsif (substr($line,37,2) eq '<=' && $line =~ s/T="(.*?)(?<!\\)" //) {
            my $subject = $1;
            $line =~ /<= (\S+)/;
            my $from = $1;
            $line =~ /.*for (.*)$/;  # .* causes it to backtrack from the right
            my @to = split / /, $1;
            my @to_domain = grep { defined $_ } map { /@(.*)/ && $1 } @to;
            $data_ref->{'mail_ids'}{$mailid}{'recipients'} = \@to if @to;
            $data_ref->{'mail_ids'}{$mailid}{'sender'} = $from;
            my $from_domain;
            if ($from =~ /\S+?\@(\S+)/) {
                $from_domain = $1;
                $data_ref->{'mail_ids'}{$mailid}{'sender_domain'} = $from_domain;
            }
            $data_ref->{'mail_ids'}{$mailid}{'subject'} = $subject;
            $data_ref->{'mail_ids'}{$mailid}{'auth_sender'} = $1 if $line =~ / A=dovecot_\S+:(\S+)/;
            $data_ref->{'mail_ids'}{$mailid}{'received_protocol'} = $1 if $line =~ / P=(\S+)/;
            $data_ref->{'mail_ids'}{$mailid}{'ident'} = $1 if $line =~ / U=(\S+)/;
            $data_ref->{'mail_ids'}{$mailid}{'who'} = who($data_ref, $data_ref->{'mail_ids'}{$mailid});

            if (!exists($data_ref->{'mail_ids'}{$mailid}{'auth_sender'})  # not locally authed
                && !exists($data_ref->{'mail_ids'}{$mailid}{'ident'})     # not ID'd as a local user
                && !exists($data_ref->{'domain2user'}{lc($from)})  # sender domain is remote
                && !grep({ !exists($data_ref->{'domain2user'}{lc($_)}) } @to_domain) ) {  # recipient domains are local
                # then this is an incoming email and we don't care about it
                delete $data_ref->{'mail_ids'}{$mailid};
            } elsif (@{$data_ref->{'mail_ids'}{$mailid}{'recipients'}} ==
                   grep { $_ =~ /\@\Q$data_ref->{'mail_ids'}{$mailid}{'sender_domain'}\E$/i }
                   @{$data_ref->{'mail_ids'}{$mailid}{'recipients'}}) {
                # if the number of recipients is the same as the number of
                # recipients that are to the sender domain, which is local,
                # then we don't care.  people can spam themselves all they
                # want.
                delete $data_ref->{'mail_ids'}{$mailid};
            } else {
                $data_ref->{'domain_responsibility'}{lc($from_domain)}++ if defined $from_domain;
                $data_ref->{'mailbox_responsibility'}{lc($from)}++;
                $data_ref->{'responsibility'}{$data_ref->{'mail_ids'}{$mailid}{'who'}}++
                    unless $data_ref->{'mail_ids'}{$mailid}{'who'} =~ /@/;
            }
        }
    }
}

sub analyze_queued_mail_data {
    my ($data) = @_;

    for my $email (values %{$data->{'mail_ids'}}) {
        next unless $email->{'in_queue'};
        $data->{'script'}{$email->{'script'}}++ if exists $email->{'script'};
        for (qw(source auth_id ident auth_sender sender sender_domain)) {
            next if $_ eq 'sender' && $email->{sender} eq 'mailer-daemon';
            next if $_ eq 'ident' && $email->{ident} eq 'mailnull';
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
    my ($data, $email) = @_;
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
    my ($data) = @_;
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

use strict;
use warnings;

use DB_File;
use Tie::File;
use Symbol ();
use IO::File;
use Fcntl qw(:flock O_RDWR O_RDONLY O_WRONLY O_CREAT);

use vars qw/$VERSION/;
$VERSION = '2015122201';

my $db_dir = '/var/spool/exim/db';
my $open_dbs = {};

sub open {
    my ($db_name) = @_;

    my $db_file = $db_dir . '/' . $db_name;
    my $lock_file = $db_file . '.lockfile';

    return undef if exists $open_dbs->{$db_name};

    die "Could not open $lock_file" if ( ! -r $lock_file );
    my $lock_file_fh = Symbol::gensym();
    sysopen($lock_file_fh, $lock_file, O_RDONLY) or die "Could not lock database $db_name: $!\n";

    flock $lock_file_fh, LOCK_SH or die "Could not flock() lockfile $lock_file: $!\n";

    tie my %db_hash, 'DB_File', $db_file or die "Could not open $db_file: $!\n";

    $open_dbs->{$db_name}{'lock_fh'} = $lock_file_fh;
    $open_dbs->{$db_name}{'tie_hash'} = \%db_hash;

    1;
}

sub read {
    my ($db_name, $sub_ref, $data_ref) = @_;

    die "Attempted to read non-opened database $db_name" if not exists $open_dbs->{$db_name};
    die "Undefined reference to parser subroutine" if (not defined $sub_ref or ref $sub_ref ne 'CODE');

    while ( my ($key, $value) = each %{$open_dbs->{$db_name}{'tie_hash'}} ) {
        $key =~ s/\x00$//;

        &{$sub_ref}($key, $value, $data_ref);
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
package SpamReport::Recent;
use common::sense;
use Storable qw(lock_store lock_retrieve);
use POSIX qw(strftime);

use vars qw/$VERSION/;
$VERSION = '2015122201';
my $logpath = "/opt/hgmods/logs/spamreport.dat";
my $cronpath = "/opt/hgmods/logs/spamreportcron.dat";
our $MAX_RETAINED = 4;

sub loadcron {
    my ($path) = @_;
    return retrievecron($path) if defined $path;
    return unless -e $cronpath;
    $path = $cronpath;
    # if the *calendar date* of $path is the same as today's
    if (POSIX::strftime("%F", localtime()) eq POSIX::strftime("%F", localtime((stat($path))[9]))) {
        return retrievecron($path)
    }
    else {
        rotatecron();
    }
    return;
}

my %cronkeys = map { ($_, 1) }
    qw( dest_domains ip_addresses logins mail_ids recipient_domains scriptdirs senders scripts
        responsibility domain_responsibility bounce_responsibility young_users young_mailboxes
    );
sub savecron {
    my ($data) = @_;
    my %newdata;
    for (keys %$data) {
        $newdata{$_} = $data->{$_}
    }
    lock_store \%newdata, $cronpath;
    #DumpFile($cronpath, \%newdata);
}

sub exitsavecron {
    my ($data) = @_;
    for (keys %$data) {
        delete $data->{$_} unless exists $cronkeys{$_}
    }
    #DumpFile($cronpath, $data);
    lock_store $data, $cronpath;
    exit
}

sub retrievecron {
    my ($path) = @_;
    lock_retrieve($path);
    #LoadFile($path)
}

sub load {
    my ($path) = @_;
    $path = $logpath unless defined $path;
    #LoadFile($path);
    lock_retrieve($path);
}

sub save {
    my ($data) = @_;
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

1;
} # end module SpamReport::Recent
BEGIN {
$INC{'SpamReport/Recent.pm'} = '/dev/null';
}

BEGIN {
package SpamReport::Maillog;

use common::sense;

use vars qw/$VERSION/;
$VERSION = '2015122201';

use Time::Local;
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
    my ($lines, $year, $end_time, $data_ref, $in_zone) = @_;
    my @lines = @$lines;
    my %days = %{$data_ref->{'OPTS'}{'dovecot_days'}};
    if ($data_ref->{'OPTS'}{'datelimit'} eq 'not today') {
        delete $days{$data_ref->{'OPTS'}{'dovecot_today'}};
    }
    elsif ($data_ref->{'OPTS'}{'datelimit'} eq 'only today') {
        %days = ($data_ref->{'OPTS'}{'dovecot_today'} => 1);
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
        next unless $_ =~ $data_ref->{'OPTS'}{'dovecot_days'};
        if ( /Login: user=<(?!__cpanel)(\S+?)>/ ) {
            my $login = $1;
            $data_ref->{'logins'}{$login}{'total_logins'}++;
            if ( /rip=(?!127\.0\.0\.1)(?!$main_ip)(\S+?),/ ) {
                $data_ref->{'logins'}{$login}{'logins_from'}{$1}++
            }
        }
    }
}

# implemented: SUSP.LOG1 account suspect if login IPs have >5 unique leading 2 octets
sub analyze_logins {
    my ($data) = @_;

    for my $login (keys %{$data->{'logins'}}) {
        my %prefix = map { /^(\d+\.\d+\.)/ or die $_; ($1, 1) } keys %{$data->{'logins'}{$login}{'logins_from'}};
        next unless scalar(keys %prefix) > 5;
        $data->{'suspects'}{'logins'}{$login} = $data->{'logins'}{$login};
    }
}

1;
} # end module SpamReport::Maillog
BEGIN {
$INC{'SpamReport/Maillog.pm'} = '/dev/null';
}

{ # begin main package
package SpamReport;

use common::sense;
use 5.008_008; use v5.8.8;

use vars qw/$VERSION/;
$VERSION = '2015122201';

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
    'timespec'      => '',
    'search_create' => undef,
    'max_queue'     => 100000,
    'check_queue'   => 1,
    'check_dbs'     => 1,
    'run_sections'  => undef,
    'read_lines'    => 10000,
    'r_cutoff'      => 1.0,
);

my $hostname = hostname_long();
my $main_ip = inet_ntoa(scalar gethostbyname($hostname || 'localhost'));

my %factories;
my %sections;

sub check_options {
    Getopt::Long::Configure(qw(gnu_getopt auto_version auto_help));
    my $check_queue;

    my $result = GetOptions(
        'start|s=s'   => \$OPTS{'start_time'},
        'end|e=s'     => \$OPTS{'end_time'},
        'max|m|n:i'   => \$OPTS{'max_queue'},
        'hours|h=i'   => \$OPTS{'search_hours'},
#        'time|t=s'    => \$OPTS{'timespec'},
        'current!'    => \$check_queue,
        'create|c=s@' => \$OPTS{'search_create'},
        'dbs!'        => \$OPTS{'check_dbs'},
        'read|r=i'    => \$OPTS{'read_lines'},
        'cron'        => \$OPTS{'cron'},
        'update'      => \$OPTS{'update'},
        'load=s'      => \$OPTS{'load'},
        'user|u=s'    => \$OPTS{'user'},
        'cutoff=i'    => \$OPTS{'r_cutoff'},
        'dump=s'      => \$OPTS{'dump'},
        'keep=i'      => \$SpamReport::Recent::MAX_RETAINED,
        'latest'      => \$OPTS{'latest'},
        'help|?'      => sub { HelpMessage() },
        'man'         => sub { pod2usage(-exitval => 0, -verbose => 2) },
        'version'     => sub { VersionMessage() },
    );

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
    for ($OPTS{'dump'}) {
        my $d;
        if (-d $_) { $d = $_ }
        elsif (m,^(/.*)/[^/+]$, && -d $1) { $d = $1 }
        elsif ($_ !~ m,/,) { $d = '.' }
        else { die "Directory doesn't exist for --dump target: $_" }

        if (! -o $d) {
            die "--dump target must be owned by root: $d"
        }
    }
    umask 0177;

    $OPTS{'start_time'} = $OPTS{'end_time'} - ($OPTS{'search_hours'} * 3600) if ( ! $OPTS{'start_time'} );

    die "Invalid number of lines to read: " . $OPTS{'read_lines'} if ( $OPTS{'read_lines'} <= 0 );

    push @{ $OPTS{'run_sections'} }, 'check_dbs' if $OPTS{'check_dbs'};
    push @{ $OPTS{'run_sections'} }, 'check_queue' if $check_queue || $OPTS{'max_queue'};
    push @{ $OPTS{'run_sections'} }, 'check_emails', 'check_logins' unless $check_queue;

    if ( $OPTS{'search_create'} ) {
        @{ $OPTS{'search_create'} } = split /,/, join(',', @{ $OPTS{'search_create'} });
        $OPTS{'run_sections'} = [ 'email_create' ];
    }

    $OPTS{'max_queue'} = 0 if $check_queue;
    $OPTS{'check_queue'} = $check_queue;

    if ($OPTS{'latest'} and $OPTS{'load'}) {
        die "only zero or one of --latest and --load can be provided"
    }
    if (($OPTS{'latest'} or $OPTS{'load'}) and $OPTS{'update'}) {
        die "--latest/--load is incompatible with --update (we wouldn't have any new data to save)"
    }
    $OPTS{'latest'} = 1 if $OPTS{'user'} and !$OPTS{'load'};


    if ($OPTS{'latest'} or $OPTS{'load'}) {
        $OPTS{'run_sections'} = []
    }


    my (%dovecot, %exim);
    for (my $i = $OPTS{'end_time'}; $i > $OPTS{'start_time'}; $i -= 3600 * 24) {
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

    my ($key, $value, $data_ref) = @_;

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
            $data_ref->{'senders'}{$mail_username}{'retries'}++ if ( $mail_hostname eq $hostname );
        }
    }

    1;
}

sub parse_ratelimit {

    my ($key, $value, $data_ref) = @_;

    # typedef struct {
    #   time_t time_stamp;
    #   /*************/
    #   int    time_usec;       /* Fractional part of time, from gettimeofday() */
    #   double rate;            /* Smoothed sending rate at that time */
    # } dbdata_ratelimit;

    my (undef, $unit, $conn_ip) = split /\//, $key;

    my ($time_stamp, $time_usec, $rate) = unpack ('l x4 i x4 d', $value);
    $data_ref->{'ip_addresses'}{$conn_ip}{'conn_rate'} = $rate
        if ($time_stamp >= $OPTS{'start_time'} and $time_stamp < $OPTS{'end_time'} );

    1;

}

sub parse_wait {
 
    my ($key, $value, $data_ref) = @_;

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

    if ($host =~ m/$RE{'spam'}{'hi_destination'}/i) {
        $data_ref->{'mail_ids'}{$_}{'send_delays'}++ for (@mail_ids);
        $data_ref->{'dest_domains'}{$1}{'delays'}++ for (@mail_ids);
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
    my ($data_ref) = @_;

    my %db_parsers = (
        'retry'            => \&parse_retries,
        'ratelimit'        => \&parse_ratelimit,
        'wait-remote_smtp' => \&parse_wait,
    );

    for my $db_name ( keys %db_parsers ) {
        SpamReport::Exim::DB::open($db_name);
        SpamReport::Exim::DB::read($db_name, $db_parsers{$db_name}, $data_ref);
        SpamReport::Exim::DB::close($db_name);
    }

    1;
}

sub parse_exim_queue {
    my ($data_ref) = @_;

    SpamReport::Exim::parse_queued_mail_data($OPTS{'start_time'}, $OPTS{'end_time'}, $OPTS{'max_queue'}, $data_ref);
}

sub parse_logs {
    my ($data, $handler, @logs) = @_;
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

            $handler->($lines, $year, $OPTS{'end_time'}, $data, $in_zone);

            $allow_year_dec = 0;
        }

        File::Nonblock::close($log);
        print "\n";

        last if $end_reached;
    }

    1;
}

sub parse_cpanel_logs {
    my ($data) = @_;
    return if $data->{'OPTS'}{'datelimit'} eq 'not today';
    parse_logs($data, \&SpamReport::Cpanel::find_email_creation, glob '/usr/local/cpanel/logs/{access_log,archive/access_log-*.gz}');
}

sub parse_exim_logs {
    parse_logs(shift, \&SpamReport::Exim::parse_exim_mainlog, glob '/var/log/exim_mainlog{,{-*,.?}.gz}');
}
sub parse_dovecot_logs {
    parse_logs(shift, \&SpamReport::Maillog::find_dovecot_logins, glob '/var/log/maillog{,{-*,.?}.gz}');
}

sub setup_cpanel {
    my ($data_ref) = @_;
    my $new;

    my $userdomains_path = '/etc/userdomains';
    my $trueuserowners_path = '/etc/trueuserowners';
    my $valiases_path = '/etc/valiases';

    %factories = (
        'user:domain' => \&SpamReport::Cpanel::map_userdomains,
        'user:owner' => \&SpamReport::Cpanel::map_userowners,
        'alias:dest'  => \&SpamReport::Cpanel::map_valiases,
    );

    %sections = (
        'email_create' => \&parse_cpanel_logs,
        'check_dbs'    => \&parse_exim_dbs,
        'check_queue'  => \&parse_exim_queue,
        'check_emails' => \&parse_exim_logs,
        'check_logins' => \&parse_dovecot_logs,
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

    $data_ref->{$_} = $new->{$_} for keys %$new;

    1;
}

sub main {
    my $data = {};
    my $loadedcron;

    STDOUT->autoflush(1);
    STDERR->autoflush(1);

    check_options() or pod2usage(2);

    unless ($OPTS{'latest'} or $OPTS{'cron'}) {
        $data = SpamReport::Recent::loadcron($OPTS{'loadcron'});
        $loadedcron = 1 if $data;
    }
    DumpFile($OPTS{'dump'}.".cron", $data) if $loadedcron && $OPTS{'dump'};

    if ($OPTS{'load'} or $OPTS{'latest'}) {
        $data = SpamReport::Recent::load($OPTS{'load'}) if $OPTS{'load'};
        $data = SpamReport::Recent::load() if $OPTS{'latest'};
        SpamReport::Output::head_info($data->{'OPTS'});
    } else {
        die "This script only supports cPanel at this time." if (not -r '/etc/userdomains' && -d '/etc/valiases');
        setup_cpanel($data);
        SpamReport::Output::head_info(\%OPTS);
        $data->{'OPTS'} = \%OPTS;
    }

    if (defined $OPTS{'user'}) {
        if (exists $data->{'domain2user'}{$OPTS{'user'}}) {
            print "Assuming you mean $data->{'domain2user'}{$OPTS{'user'}} by $OPTS{'user'}\n";
            $OPTS{'user'} = $data->{'domain2user'}{$OPTS{'user'}};
        }
        if (!getpwnam($OPTS{'user'})) {
            die "No such user: $OPTS{'user'}"
        }
    }

    if ($OPTS{'cron'}) {
        $OPTS{'datelimit'} = 'not today';
        for my $section ( @{ $OPTS{'run_sections'} } ) {
            next if $section eq 'check_queue';
            $sections{$section}($data);
        }
        SpamReport::Cpanel::young_users($data);
        SpamReport::Recent::exitsavecron($data);
    }
    elsif ($loadedcron) {
        $OPTS{'datelimit'} = 'only today';
        for my $section ( @{ $OPTS{'run_sections'} } ) {
            $sections{$section}($data);
        }
    }
    else {
        for my $section ( @{ $OPTS{'run_sections'} } ) {
            $sections{$section}($data);
        }
        SpamReport::Cpanel::young_users($data);
    }
    DumpFile($OPTS{'dump'}.".scan", $data) if $OPTS{'dump'};

    #if ( $OPTS{'sections'} ) {
    #    SpamReport::Output::email_search_results($data);
    #}
    #else {
    SpamReport::Recent::save($data) if $OPTS{'update'};
    if (!$OPTS{'update'}) {
        SpamReport::Output::analyze_results($data);
        if ($OPTS{'user'}) {
            SpamReport::Output::analyze_user_results($data, $OPTS{'user'});
            SpamReport::Output::print_user_results($data, $OPTS{'user'});
        } else {
            SpamReport::Output::print_results($data) unless $OPTS{'cron'};
        }
    }
    DumpFile($OPTS{'dump'}.".post", $data) if $OPTS{'dump'};
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

Options:

    -s <time>   | --start=<time>
    -e <time>   | --end=<time>
    -h <hours>  | --hours=<hours>
        (default: 72 hours)
        (NB. spamreport has a minimum granularity of one calendar day)

                | --current             : check the exim queue
    -m          | --max                 : check the entire queue
    -n <limit>  | --max=<limit>         : check up to # emails in the queue

                | --dbs                 : check exim databases

    -u <user>   | --user=<user>         : report on a user, implies --latest unless --load is present

                | --cron                : gather crondata and save it, without analysis or output
                | --update              : gather fulldata and save it.  uses crondata if fresh
                | --latest              : use fulldata if present
                | --load=path/to/file   : load data from file
                | --loadcron=/to/file   : load crondata from file
                | --keep=<number>       : preserve # of rotated logs

                | --dump=path/to/file   : save (human-readable) YAML files to
                                          $path.cron  : --cron seeded data, if one was loaded
                                          $path.scan  : pre-analysis data, after scans are done
                                          $path.post  : post-analysis data

                | --help
                | --man
                | --version

crondata: a serialized data structure containing data from calendar days prior
to today's.

fulldata: a serialized data structure containing all data, including today's.

Usage:

  spamreport              # get a report.  if crondata is fresh, it is used
  spamreport -u <user>    # get user report.  fulldata is used if present
  spamreport --cron       # refresh crondata
  spamreport --update     # get fulldata and save it
  spamreport --latest     # get a report based on the last-saved fulldata

