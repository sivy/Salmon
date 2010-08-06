#!/usr/bin/env perl
# 20-key-retriever.t

use lib qw(../lib);

use strict;
use warnings;
use Carp::Always;

use Test::More qw (no_plan);

use MagicSignatures::KeyRetriever qw(lookup_public_key lookup_private_key);

my $TEST_PUBLIC_KEY = join(
    '',
    (   'RSA.mVgY8RN6URBTstndvmUUPb4UZTdwvwmddSKE5z_jvKUEK6yk1',
        'u3rrC9yN8k6FilGj9K0eeUPe2hf4Pj-5CmHww==',
        '.AQAB',
        '.Lgy_yL3hsLBngkFdDw1Jy9TmSRMiH6yihYetQ8jy-jZXdsZXd8V5',
        'ub3kuBHHk4M39i3TduIkcrjcsiWQb77D8Q==',
    )
);

is( lookup_public_key('user@example.com'), $TEST_PUBLIC_KEY, 'lookup_public_key' );

use WWW::Finger::Webfinger;

my $wf = WWW::Finger::Webfinger->new('steveivy@monkinetic.status.net');

ok($wf);

diag explain $wf;


