#!/usr/bin/env perl
# 30-magic-algorithms.t

use lib qw(../lib);

use strict;
use warnings;

use Test::More qw (no_plan);

use Salmon::MagicSignatures::SignatureAlgRsaSha256;
use Crypt::RSA;
use Crypt::RSA::DataFormat qw(h2osp i2osp);
use Crypt::RSA::Key::Private::Magic;
use MIME::Base64::URLSafe;
use Carp::Always;

# Crypt::RSA::SS::PKCS1v15_SHA256 is a subclass (found in this distribution) that uses SHA256 instead of SHA1, MD5, or MD2
require_ok('Salmon::Crypt::RSA::SS::PKCS1v15_SHA256');

my $rsa = new Crypt::RSA( ES => 'PKCS1v15', SS => { Module => 'Salmon::Crypt::RSA::SS::PKCS1v15_SHA256' } );

ok( $rsa, 'Crypt::RSA created' );

# KEY_STR is the test key from the salmon playground
my $KEY_STR =
    "RSA.mVgY8RN6URBTstndvmUUPb4UZTdwvwmddSKE5z_jvKUEK6yk1u3rrC9yN8k6FilGj9K0eeUPe2hf4Pj-5CmHww==.AQAB.Lgy_yL3hsLBngkFdDw1Jy9TmSRMiH6yihYetQ8jy-jZXdsZXd8V5ub3kuBHHk4M39i3TduIkcrjcsiWQb77D8Q==";

my $TEST_MESSAGE = "test string";

# TEST_SIG is the salmon playground signature for the message "test string"
my $TEST_SIG = 'mNpBIpTUOESnuQMlS8aWZ4hwdSwWnMstrn0F3L9GHDXa238fN3Bx3Rl0yvVESM_eZuocLsp9ubUrYDu83821fQ==';

diag "test signature object";

my $signer = Salmon::MagicSignatures::SignatureAlgRsaSha256->new($KEY_STR);

is( $signer->to_string, $KEY_STR, 'to_string outputs same string as the input to init_from_string' );

my $signature_b64 = $signer->sign($TEST_MESSAGE);

is( $signature_b64, $TEST_SIG, "SignatureAlgRsaSha256 signature matches salmon playground rawsignatures output" );

diag "test sign and verify";

my ( $gen_public, $gen_private ) = $rsa->keygen(
    Identity  => 'Test User <test@example.org>',
    Size      => 1024,
    Password  => 'test',
    Verbosity => 1,
) or die $rsa->errstr();

ok( $gen_public,  'public key generated' );
ok( $gen_private, 'private key generated' );

## this will be used from MagicEnvelopeProtocol
my $signer2 = MagicSignatures::Algorithms::SignatureAlgRsaSha256->new($gen_private);

my $signature = $signer2->sign("test 2");

# 0 = not the full keypair. this is what you would publish for a user
my $public_key_str = $signer2->to_string(0);

## this will be used from MagicEnvelopeProtocol
my $verifier = MagicSignatures::Algorithms::SignatureAlgRsaSha256->new($public_key_str);

is( $verifier->to_string, $public_key_str, 'signer from public key string produces same string from to_string' );
ok( $verifier->verify( "test 2", $signature ), 'message verified for signer2' );

