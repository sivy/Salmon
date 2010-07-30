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

#use MagicSignatures::Algorithms::SignatureAlgRsaSha256;

require_ok('Crypt::RSA::SS::PKCS1v15_SHA256');

my $rsa = new Crypt::RSA ( ss => { Module => 'Crypt::RSA::SS::PKCS1v15_SHA256' } );

ok($rsa, 'Crypt::RSA created');

# diag explain $rsa;

my $key_text = 'RSA.mVgY8RN6URBTstndvmUUPb4UZTdwvwmddSKE5z_jvKUEK6yk1u3rrC9yN8k6FilGj9K0eeUPe2hf4Pj-5CmHww==.AQAB.Lgy_yL3hsLBngkFdDw1Jy9TmSRMiH6yihYetQ8jy-jZXdsZXd8V5ub3kuBHHk4M39i3TduIkcrjcsiWQb77D8Q==';

# sub key_from_string {
#   my ($str_key) = @_;
#   $str_key =~ s/\s+//;
#   $str_key =~ /RSA\.(?P<mod>[^\.]+)\.(?P<exp>[^\.]+)(?:\.(?P<private_exp>[^\.]+))?/;

#   my ($mod, $exp, $private_exp) = ($1, $2, $3);

#   $y = Math::BigInt->new(1234567);	# unrounded
# 	print Math::BigInt->precision(4),"\n";	# set 4, print 4
	

#   $mod = urlsafe_b64decode($mod);
#   $exp = urlsafe_b64decode($exp)
#   $private_exp = urlsafe_b64decode($private_exp);

#   return [$mod, $exp, $private_exp];
# }

my $keystr = "RSA.mVgY8RN6URBTstndvmUUPb4UZTdwvwmddSKE5z_jvKUEK6yk1u3rrC9yN8k6FilGj9K0eeUPe2hf4Pj-5CmHww==.AQAB.Lgy_yL3hsLBngkFdDw1Jy9TmSRMiH6yihYetQ8jy-jZXdsZXd8V5ub3kuBHHk4M39i3TduIkcrjcsiWQb77D8Q==";
my $key = Crypt::RSA::Key::Private::Magic->from_string($keystr);

my $signature = $rsa->sign(
 			 Key => $key, 
 			 Message =>"steve");

my $encoded = urlsafe_b64encode($signature);

is ($encoded, 'NaJ5ON3WLqWiBC2is1wST9QhyUIbEv21zc3j1ba4AmlSn0Vor4PHCMZNZ8VkykDtv4TgxJqHjPCuWFkN1snc5g==', "it's alive!!!");
