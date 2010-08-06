#!/usr/bin/env perl
# 00-compile.t
use lib qw(../lib);

use strict;
use warnings;

use Test::More qw (no_plan);

# require_ok('MagicSignatures');
require_ok('Salmon::MagicSignatures::MagicEnvelope');
require_ok('Salmon::MagicSignatures::MagicEnvelopeProtocol');
require_ok('Salmon::MagicSignatures::SignatureAlgRsaSha256');
require_ok('Salmon::MagicSignatures::KeyRetriever');
require_ok('Salmon::Crypt::RSA::SS::PKCS1v15_SHA256');

require_ok('Salmon::Client');
