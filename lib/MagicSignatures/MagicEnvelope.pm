#!/usr/bin/env perl

package MagicSignatures::MagicEnvelope;

# use MagicSignatures::KeyRetriever;

our $ENCODING     = 'base64url';
our $_ATOM_NS_URL = 'http://www.w3.org/2005/Atom';
our $_ME_NS_URL   = 'http://salmon-protocol.org/ns/magic-env';
our $_ATOM_NS     = "{$_ATOM_NS_URL}";
our $_ME_NS       = "{$_ME_NS_URL}";

sub new {
    my ( $class, $data, $signer_uri, $signer_key, $data_type, $encoding, $alg, ) = @_;
    my $self = {
        data       => $data,
        signer_uri => $signer_uri,
        signer_key => $signer_key,
        data_type  => $data_type,
        encoding   => $encoding,
        alg        => $alg,
    };

    bless( $self, $class );
    return $self;
}

1;
