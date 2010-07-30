#!/usr/bin/env perl

package MagicSignatures::MagicEnvelope;

use MIME::Base64::URLSafe;

sub new {
    my $obj = bless {}, shift;
    return $obj;
}

sub base64_urlencode {
    return urlsafe_b64encode(@_);
}
