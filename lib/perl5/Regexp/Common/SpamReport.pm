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
