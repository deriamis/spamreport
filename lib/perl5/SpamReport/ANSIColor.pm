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
