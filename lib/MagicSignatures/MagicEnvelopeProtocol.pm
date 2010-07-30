#!/usr/bin/env perl

package MagicSignatures::MagicEnvelopeProtocol;

use MagicSignatures::KeyRetriever;

use Crypt::RSA;

our $ENCODING     = 'base64url';
our $_ATOM_NS_URL = 'http://www.w3.org/2005/Atom';
our $_ME_NS_URL   = 'http://salmon-protocol.org/ns/magic-env';
our $_ATOM_NS     = "{$_ATOM_NS_URL}";
our $_ME_NS       = "{$_ME_NS_URL}";

sub new {
    my $obj = bless {}, shift;
    return $obj;
}

sub get_private_key {
    my $self = shift;
    my ($signer_uri) = @_;
    return KeyRetriever::lookup_private_key($signer_uri);
}

sub get_public_key {
    my $self = shift;
    my ($signer_uri) = @_;
    return KeyRetriever::lookup_public_key($signer_uri);
}

sub get_signer_uri {
    my $self = shift;
    my ($data) = @_;

    # parse data as XML

    # get all (xpath) {ATOM_NS}author/{ATOM_NS}uri

    # return first uri found

}

1;
