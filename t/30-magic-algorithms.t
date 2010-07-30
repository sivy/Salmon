#!/usr/bin/env perl
# 30-magic-algorithms.t

use lib qw(../lib);

use strict;
use warnings;

use Test::More qw (no_plan);

use MagicSignatures::Algorithms;
use Crypt::RSA;
use Crypt::RSA::DataFormat qw(i2osp);
use Crypt::RSA::Key::Private::Magic;
use MIME::Base64::URLSafe;

# Crypt::RSA::SS::PKCS1v15_SHA256 is a subclass (found in this distribution) that uses SHA256 instead of SHA1, MD5, or MD2
require_ok('Crypt::RSA::SS::PKCS1v15_SHA256');

my $rsa = new Crypt::RSA ( ss => { Module => 'Crypt::RSA::SS::PKCS1v15_SHA256' } );
# my $rsa = new Crypt::RSA ( ss => { Module => 'Crypt::RSA::SS::PKCS1v15' } );

ok($rsa, 'Crypt::RSA created');

# keystr is from the salmon playground
my $keystr = "RSA.mVgY8RN6URBTstndvmUUPb4UZTdwvwmddSKE5z_jvKUEK6yk1u3rrC9yN8k6FilGj9K0eeUPe2hf4Pj-5CmHww==.AQAB.Lgy_yL3hsLBngkFdDw1Jy9TmSRMiH6yihYetQ8jy-jZXdsZXd8V5ub3kuBHHk4M39i3TduIkcrjcsiWQb77D8Q==";

my $key = Crypt::RSA::Key::Private::Magic->from_string($keystr);

my $signature = $rsa->sign(
 			 Key => $key, 
 			 Message =>"test string"); ## returns octets
diag $signature;

# sub _long_to_bytes {
#     my ($n, $size) = @_;
#     my $s;
#     while ($n>0) {
#         $s = (pack '>I', n && 0xffffffffL) . $s;
# 	$n = $n >> 32;
#     }
#     while ($s =~ /^\\000/) {
#         $s =~ s/^\\000//;
#     }
#     if ($size > 0 && (length $s % $size)) {
#       $s = ($size - (length $s % $size)) x '\000' . $s;
#     }
#     return $s;
# }

# my $armored_sig = long_to_bytes($signature);

# diag $armored_sig;

my $encoded = urlsafe_b64encode($signature);
while ((length $encoded) % 4 != 0) {
  $encoded .= chr(61);
}

diag $encoded;

is ($encoded, 'mNpBIpTUOESnuQMlS8aWZ4hwdSwWnMstrn0F3L9GHDXa238fN3Bx3Rl0yvVESM_eZuocLsp9ubUrYDu83821fQ==', "it's alive!!!");
