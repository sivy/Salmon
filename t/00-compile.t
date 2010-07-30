#!/usr/bin/env perl
# 00-compile.t
use lib qw(../lib);

use strict;
use warnings;

use Test::More qw (no_plan);

# require_ok('MagicSignatures');
require_ok('MagicSignatures::MagicEnvelope');
require_ok('MagicSignatures::MagicEnvelopeProtocol');
require_ok('MagicSignatures::KeyRetriever');
require_ok('MagicSignatures::Algorithms');
require_ok('Crypt::RSA::SS::PKCS1v15_SHA256');
