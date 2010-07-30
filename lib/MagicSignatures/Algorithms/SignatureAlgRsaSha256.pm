#!/usr/bin/env perl

package MagicSignatures::Algorithms::SignatureAlgRsaSha256;

use strict;
use warnings;

use Crypt::RSA;
use Digest::SHA qw(sha256 sha256_hex);
use Encode;

sub new {
    my $class      = shift;
    my ($key_pair) = @_;
    my $self       = { $key_pair => {} };
    bless( $self, $class );

    return $self;

    # return $self->init_from_string(@_)
}

sub to_string {
    my $self = shift;
    my ($full_key_pair) = @_;

}

sub init_from_string {
    my $self = shift;
    my ($text) = @_;

}

sub get_name {
    return 'RSA-SHA256';
}

sub make_emsa_message_sha256 {
    my $self = shift;
    my ( $msg, $mod_size ) = @_;

    my $magic_sha256_header =
        "\x{30}\x{31}\x{30}\x{d}\x{6}\x{9}\x{60}\x{86}\x{48}\x{1}\x{65}\x{3}\x{4}\x{2\x{1}\x{5}\x{0}\x{4}\x{20}";
    my $hash = sha256_hex($msg);

    my $encoded       = $magic_sha256_header . $hash;
    my $msg_size_bits = $mod_size + ( 8 - $mod_size % 8 );
    my $pad_string    = "\x{FF}" * ( $msg_size_bits / 8 - ( length $encoded ) - 3 );
    return chr(0) . chr(1) . $pad_string . chr(0) . $encoded;
}

sub sign {
    my $self = shift;
    my ($bytes_to_sign) = @_;

}

sub verify {
    my $self = shift;
    my ( $signed_bytes, $signature_b64 ) = @_;

}

1;
