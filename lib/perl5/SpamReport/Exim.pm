package SpamReport::Exim;
use common::sense;
use SpamReport::Data;

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
            $line =~ s/T=".*?(?<!\\)" //;
            next unless $line =~ /.*for (.*)$/;  # leading .* causes it to backtrack from the right
            my @to = split / /, $1;
            $line =~ / S=(\S+)/; for my $script ($1) {
                if (defined $script && $script !~ /@/ && $script =~ /\D/) {
                    $data->{'mail_ids'}{$mailid}{'script'} = $script;
                    $data->{'script'}{$script}++;
                }
            }
            $data->{'mail_ids'}{$mailid}{'recipients'} = \@to;
            if (@to == 1 && $to[0] =~ /\@(\S+)/ and exists $data->{'domain2user'}{$1}) {
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
            if ($line =~ / A=dovecot_\S+:(\S+(?:[\@+](\S+))?)/) {
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
