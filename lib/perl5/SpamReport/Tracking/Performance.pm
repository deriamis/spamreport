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
