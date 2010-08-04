#!/usr/bin/env perl
# 10-magic-envelopes.t
use lib qw(../lib);

use strict;
use warnings;
# use Carp::Always;

use Test::More qw (no_plan);

use MagicSignatures::MagicEnvelope;
use MagicSignatures::MagicEnvelopeProtocol;

my $TEST_ATOM = <<ATOM;
<?xml version='1.0' encoding='UTF-8'?>
    <entry xmlns='http://www.w3.org/2005/Atom'>
    <id>tag:example.com,2009:cmt-0.44775718</id>
      <author><name>test\@example.com</name><uri>acct:test\@example.com</uri>
      </author>
      <content>Salmon swim upstream!</content>
      <title>Salmon swim upstream!</title>
      <updated>2009-12-18T20:04:03Z</updated>
    </entry>
ATOM

my $TEST_ATOM_MULTIAUTHOR = <<MATOM;
<?xml version='1.0' encoding='UTF-8'?>
    <entry xmlns='http://www.w3.org/2005/Atom'>
    <id>tag:example.com,2009:cmt-0.44775718</id>
      <author><name>alice\@example.com</name><uri>acct:alice\@example.com</uri>
      </author>
      <author><name>bob\@example.com</name><uri>acct:bob\@example.com</uri>
      </author>
      <content>Salmon swim upstream!</content>
      <title>Salmon swim upstream!</title>
      <updated>2009-12-18T20:04:03Z</updated>
    </entry>
MATOM

my $SIGNER_URI           = 'acct:test@example.com';
my $TEST_PRIVATE_KEY = join(
    '',
    (   'RSA.mVgY8RN6URBTstndvmUUPb4UZTdwvwmddSKE5z_jvKUEK6yk1',
        'u3rrC9yN8k6FilGj9K0eeUPe2hf4Pj-5CmHww==',
        '.AQAB',
        '.Lgy_yL3hsLBngkFdDw1Jy9TmSRMiH6yihYetQ8jy-jZXdsZXd8V5',
        'ub3kuBHHk4M39i3TduIkcrjcsiWQb77D8Q==',
    )
);

my $protocol = MagicSignatures::MagicEnvelopeProtocol->new();

is( $protocol->get_signer_uri($TEST_ATOM), 'acct:test@example.com', 'signer uri extracted');
is( $protocol->get_signer_uri($TEST_ATOM_MULTIAUTHOR), 'acct:alice@example.com', 'signer uri extracted');

ok($protocol->is_allowed_signer($TEST_ATOM, 'acct:test@example.com'), 'test user identified as allowed signer');
ok($protocol->is_allowed_signer($TEST_ATOM_MULTIAUTHOR, 'acct:alice@example.com'), 'test user identified as allowed signer');
ok(!$protocol->is_allowed_signer($TEST_ATOM_MULTIAUTHOR, 'acct:bob@example.com'), 'second test user identified as not an allowed signer');

diag "test magic envelope";

my $env = MagicSignatures::MagicEnvelope->new( 
					      raw_data => $TEST_ATOM, #data to sign 
					      signer_uri => $SIGNER_URI, #sign with this user's priv key
					      signer_key => $TEST_PRIVATE_KEY, 
					      data_type=>'application/atom+xml', # MIME of the content
					      encoding => 'base64url',  # encoder
					      alg => 'RSA-SHA256', # sig algorithm
					     );

ok($env, 'created an envelope from params'); 

my $xml = $env->to_xml;

ok($xml, 'got something out of to_xml (need better checking)');

# my $env2 = MagicSignatures::MagicEnvelope->init_from_xml(
# 							'application/magic-envelope+xml', # MIME to create
# 							$xml, 
# 							0
# 							);

