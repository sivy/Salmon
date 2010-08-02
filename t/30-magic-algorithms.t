#!/usr/bin/env perl
# 30-magic-algorithms.t

use lib qw(../lib);

use strict;
use warnings;

use Test::More qw (no_plan);

use MagicSignatures::Algorithms::SignatureAlgRsaSha256;
use Crypt::RSA;
use Crypt::RSA::DataFormat qw(h2osp i2osp);
use Crypt::RSA::Key::Private::Magic;
use MIME::Base64::URLSafe;

# Crypt::RSA::SS::PKCS1v15_SHA256 is a subclass (found in this distribution) that uses SHA256 instead of SHA1, MD5, or MD2
require_ok('Crypt::RSA::SS::PKCS1v15_SHA256');

my $rsa = new Crypt::RSA( ES => 'PKCS1v15', SS => { Module => 'Crypt::RSA::SS::PKCS1v15_SHA256' } );

ok( $rsa, 'Crypt::RSA created' );

# KEY_STR is the test key from the salmon playground
my $KEY_STR =
    "RSA.mVgY8RN6URBTstndvmUUPb4UZTdwvwmddSKE5z_jvKUEK6yk1u3rrC9yN8k6FilGj9K0eeUPe2hf4Pj-5CmHww==.AQAB.Lgy_yL3hsLBngkFdDw1Jy9TmSRMiH6yihYetQ8jy-jZXdsZXd8V5ub3kuBHHk4M39i3TduIkcrjcsiWQb77D8Q==";

my $TEST_MESSAGE = "test string";

# TEST_SIG is the salmon playground signature for the message "test string"
my $TEST_SIG = 'mNpBIpTUOESnuQMlS8aWZ4hwdSwWnMstrn0F3L9GHDXa238fN3Bx3Rl0yvVESM_eZuocLsp9ubUrYDu83821fQ==';

my $key = Crypt::RSA::Key::Private::Magic->from_string($KEY_STR);

my $signature = $rsa->sign(
    Key     => $key,
    Message => $TEST_MESSAGE,
);    ## returns octets

# diag $signature;

my $encoded = urlsafe_b64encode($signature);
while ( ( length $encoded ) % 4 != 0 ) {
    $encoded .= chr(61);
}

# diag $encoded;

diag "test that sig matches the sig produced by the salmon playground app";

is( $encoded,
    $TEST_SIG,
    "signature matches salmon playground rawsignatures output"
);

diag "test signature object";

my $signer = MagicSignatures::Algorithms::SignatureAlgRsaSha256->new($KEY_STR);

diag $signer->to_string;

my $signature_b64 = $signer->sign($TEST_MESSAGE);

is( $signature_b64,
    $TEST_SIG,
    "SignatureAlgRsaSha256 signature matches salmon playground rawsignatures output"
);

diag "test sign and verify";

my ($gen_public, $gen_private) = 
        $rsa->keygen ( 
            Identity  => 'Test User <test@example.org>',
            Size      => 1024,  
            Password  => 'test', 
            Verbosity => 1,
        ) or die $rsa->errstr();

ok ($gen_public, 'public key generated');
ok ($gen_private, 'private key generated');

my $sig = $rsa->sign(
    Key     => $gen_private,
    Message => "test 2",
);    ## returns octets

ok($sig, "new sig created from generated private key");

my $encoded_sig = urlsafe_b64encode($sig);
while ( ( length $encoded_sig ) % 4 != 0 ) {
    $encoded_sig .= chr(61);
}

my $decoded_sig = urlsafe_b64decode($encoded_sig);

my $verify = $rsa->verify (
    Message    => "test 2", 
    Signature  => $decoded_sig, 
    Key        => $gen_public
);

ok ($verify, "created sig checks out with generated public key");

#my $verify2 = $signer->verify("test 2", $encoded_sig);

#ok ($verify2, "created sig checked out by signer with generated");

