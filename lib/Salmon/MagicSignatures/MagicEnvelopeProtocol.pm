#!/usr/bin/env perl

package Salmon::MagicSignatures::MagicEnvelopeProtocol;

# use Salmon::MagicSignatures::KeyRetriever;

use Crypt::RSA;
use XML::XPath;
use MIME::Base64::URLSafe;

use Data::Dumper;

our $ENCODING     = 'base64url';
our $_ATOM_NS_URL = 'http://www.w3.org/2005/Atom';
our $_ME_NS_URL   = 'http://salmon-protocol.org/ns/magic-env';
our $_ATOM_NS     = "atom";
our $_ME_NS       = "me";

sub new {
    my $class = shift;
    my $obj   = {};
    bless $obj, $class;
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
    my $xp = new XML::XPath->new( xml => $data );

    # print Dumper($xp);
    $xp->set_namespace( $_ATOM_NS, $_ATOM_NS_URI );
    $xp->set_namespace( $_ME_NS,   $_ME_NS_URI );
    $xp->set_namespace( 'thr',     'http://purl.org/syndication/thread/1.0' );

    #my $nodes_path = $_ATOM_NS . 'author/' . $_ATOM_NS . 'uri';
    my $nodes_path = 'entry/author/uri';

    # get all (xpath) {ATOM_NS}author/{ATOM_NS}uri
    my $nodeset = $xp->findnodes($nodes_path);

    # return first uri found
    for my $node ( $nodeset->get_nodelist ) {
        return $self->normalize_user( $node->string_value ) if $node->string_value;
    }
}

sub is_allowed_signer {
    my $self = shift;
    my ( $data, $user_uri ) = @_;
    $user_uri = $self->normalize_user($user_uri);
    print $user_uri . " eq " . $self->get_signer_uri($data) . "?\n";
    return $user_uri eq $self->get_signer_uri($data);
}

sub encode_data {
    my $self = shift;
    my ($data) = @_;

    return urlsafe_b64encode($data);
}

sub normalize_user {
    my $self = shift;
    my ($user_id) = @_;
    if (   substr( $user_id, 0, 5 ) eq 'http:'
        || substr( $user_id, 0, 6 ) eq 'https:'
        || substr( $user_id, 0, 5 ) eq 'acct:' )
    {
        return $user_id;
    }

    if ( $user_id =~ /\@/ ) {
        return "acct:$user_id";
    }
    return "http://$user_id";
}

1;
