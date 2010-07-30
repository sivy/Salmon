#!/usr/bin/env perl
# 10-magic-envelopes.t
use lib qw(../lib);

use strict;
use warnings;

use Test::More qw (no_plan);

my $TEST_ATOM = <<ATOM;
<?xml version='1.0' encoding='UTF-8'?>
<entry xmlns='http://www.w3.org/2005/Atom'>
  <id>tag:example.com,2009:cmt-0.44775718</id>
  <author>
    <name>Test</name>
    <uri>acct:test\@example.com</uri>
  </author>
  <content>Salmon swim upstream!</content>
  <title>Salmon swim upstream!</title>
  <updated>2009-12-18T20:04:03Z</updated>
</entry>
ATOM

my $SIGNER           = 'steveivy@gmail.com';
my $TEST_PRIVATE_KEY = join(
    '',
    (   'RSA.mVgY8RN6URBTstndvmUUPb4UZTdwvwmddSKE5z_jvKUEK6yk1',
        'u3rrC9yN8k6FilGj9K0eeUPe2hf4Pj-5CmHww==',
        '.AQAB',
        '.Lgy_yL3hsLBngkFdDw1Jy9TmSRMiH6yihYetQ8jy-jZXdsZXd8V5',
        'ub3kuBHHk4M39i3TduIkcrjcsiWQb77D8Q==',
    )
);

use MagicSignatures::MagicEnvelope;

my $env = MagicSignatures::MagicEnvelope->new( $TEST_ATOM, $SIGNER, $TEST_PRIVATE_KEY, 'application/atom+xml',
    'base64url', 'RSA-SHA256', );

diag explain $env;

ok($env);
