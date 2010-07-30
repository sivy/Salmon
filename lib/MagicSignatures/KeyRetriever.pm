#!/usr/bin/env perl

package MagicSignatures::KeyRetriever;

use Exporter;
@MagicSignatures::KeyRetriever::ISA = qw( Exporter );
use vars qw( @EXPORT_OK );
@EXPORT_OK = qw( lookup_public_key lookup_private_key );

use WWW::Finger::WebFinger;

sub lookup_public_key {
    my ($signer_uri) = @_;

    # @TODO(sivy): use webfinger to find the public key
    return join(
        '',
        (   'RSA.mVgY8RN6URBTstndvmUUPb4UZTdwvwmddSKE5z_jvKUEK6yk1',
            'u3rrC9yN8k6FilGj9K0eeUPe2hf4Pj-5CmHww==',
            '.AQAB',
            '.Lgy_yL3hsLBngkFdDw1Jy9TmSRMiH6yihYetQ8jy-jZXdsZXd8V5',
            'ub3kuBHHk4M39i3TduIkcrjcsiWQb77D8Q==',
        )
    );
}

sub lookup_private_key {
    my ($signer_uri) = @_;

    # @TODO(sivy) implement or eliminate

}

1;
