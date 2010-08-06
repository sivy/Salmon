#!/usr/bin/env perl

package Salmon::Client;

use Salmon::MagicSignatures::MagicEnvelope;

our $NS_REPLIES  = "http://salmon-protocol.org/ns/salmon-replies";
our $NS_MENTIONS = "http://salmon-protocol.org/ns/salmon-mention";

sub new {
    my $class = shift;
    my $self  = {};
    bless $self, $class;
    return $self;
}

sub post {
    my $self = shift;
    my ( $endpoint_url, $atom_xml, $author, $author_private_key ) = @_;

    # create a magic envelope from the Atom XML
    my $env = Salmon::MagicSignatures::MagicEnvelope->new(
        raw_data   => $atom_xml,                 #data to sign
        signer_uri => $author,                   #sign with this user's priv key
        signer_key => $author_private_key,
        data_type  => 'application/atom+xml',    # MIME of the content
        encoding   => 'base64url',               # encoder
        alg        => 'RSA-SHA256',              # sig algorithm
    );
    my $env_xml = $env->to_xml;

    # create http client
    use LWP::UserAgent;
    $ua = LWP::UserAgent->new;

    my $req = HTTP::Request->new( POST => $endpoint );
    print "########## " . $req->uri;

    # setup headers
    $req->content_type('application/magic-envelope+xml');
    $req->content($env_xml);

    # post the message
    my $res = $ua->request($req);
    print $res->as_string;

}

1;
