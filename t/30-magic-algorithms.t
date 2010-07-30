#!/usr/bin/env perl
# 30-magic-algorithms.t

use lib qw(../lib);

use strict;
use warnings;

use Test::More qw (no_plan);

use MagicSignatures::Algorithms;
use Crypt::RSA;
use Crypt::RSA::Key::Private::Magic;
use MIME::Base64::URLSafe;

# Crypt::RSA::SS::PKCS1v15_SHA256 is a subclass (found in this distribution) that uses SHA256 instead of SHA1, MD5, or MD2
require_ok('Crypt::RSA::SS::PKCS1v15_SHA256');

my $rsa = new Crypt::RSA ( ss => { Module => 'Crypt::RSA::SS::PKCS1v15_SHA256' } );

ok($rsa, 'Crypt::RSA created');

# keystr is from the salmon playground
my $keystr = "RSA.mVgY8RN6URBTstndvmUUPb4UZTdwvwmddSKE5z_jvKUEK6yk1u3rrC9yN8k6FilGj9K0eeUPe2hf4Pj-5CmHww==.AQAB.Lgy_yL3hsLBngkFdDw1Jy9TmSRMiH6yihYetQ8jy-jZXdsZXd8V5ub3kuBHHk4M39i3TduIkcrjcsiWQb77D8Q==";

my $key = Crypt::RSA::Key::Private::Magic->from_string($keystr);

my $signature = $rsa->sign(
 			 Key => $key, 
 			 Message =>"steve");

my $encoded = urlsafe_b64encode($signature);

is ($encoded, 'NaJ5ON3WLqWiBC2is1wST9QhyUIbEv21zc3j1ba4AmlSn0Vor4PHCMZNZ8VkykDtv4TgxJqHjPCuWFkN1snc5g==', "it's alive!!!");
