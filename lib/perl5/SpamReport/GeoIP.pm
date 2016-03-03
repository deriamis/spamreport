package SpamReport::GeoIP;
use Geo::IPfree;
use IP::Country::Fast;
use vars qw($VERSION);
$VERSION = '2016022601';

my ($geo, $ipc);

sub init {
    $geo = Geo::IPfree->new;
    $geo->Faster;
    $ipc = IP::Country::Fast->new;
}

sub lookup {
    my ($ip) = @_;
    return $ipc->inet_atocc($ip) || ($geo->LookUp($ip))[0]
}

1;
} # end module SpamReport::GeoIP
