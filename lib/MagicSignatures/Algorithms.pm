#!/usr/bin/env perl

package MagicSignatures::Algorithms;

package MagicSignatures::SignatureAlgRsaSha256;

sub new {
    my $class      = shift;
    my ($key_pair) = @_;
    my $self       = { $key_pair => {} };
    bless( $self, $class );

    #  return $self->init_from_string(@_)
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
