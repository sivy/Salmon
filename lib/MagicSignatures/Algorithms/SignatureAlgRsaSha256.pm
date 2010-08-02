#!/usr/bin/env perl

package MagicSignatures::Algorithms::SignatureAlgRsaSha256;

use strict;
use warnings;

use Crypt::RSA;
use Crypt::RSA::DataFormat qw(h2osp i2osp);
use Crypt::RSA::Key::Private::Magic;
use MIME::Base64::URLSafe;

sub new {
    my $class = shift;
    my ($key) = @_;
    my $self  = { $key => undef };
    bless( $self, $class );

    if ( ref $key ) {
        $self->{key} = $key;
    }
    else {
        $self->init_from_string($key);
    }

    return $self;
}

sub get_name {
    return 'RSA-SHA256';
}

sub to_string {
    my $self = shift;
    my ($full_key_pair) = @_;
    unless ( defined $full_key_pair ) {
        $full_key_pair = 1;
    }
    return $self->{key}->to_string($full_key_pair);
}

sub init_from_string {
    my $self = shift;
    my ($key_str) = @_;

    my $key;
    eval { $key = Crypt::RSA::Key::Private::Magic->from_string($key_str); };
    unless ($@) {
        $self->{key} = $key;
    }
}

sub sign {
    my $self = shift;
    my ($bytes_to_sign) = @_;

    my $rsa = new Crypt::RSA( ES => 'PKCS1v15', SS => { Module => 'Crypt::RSA::SS::PKCS1v15_SHA256' } );

    my $signature = $rsa->sign(
        Key     => $self->{key},
        Message => $bytes_to_sign,
    );

    my $encoded = urlsafe_b64encode($signature);
    while ( ( length $encoded ) % 4 != 0 ) {
        $encoded .= chr(61);
    }
    return $encoded;
}

sub verify {
    my $self = shift;
    my ( $signed_bytes, $signature_b64 ) = @_;

    my $decoded_sig = urlsafe_b64decode($signature_b64);

    # my $verify = $rsa->verify(
    #     Message   => $signed_bytes,
    #     Signature => $decoded_sig,
    #     Key       => $gen_public
    # );
    #    return $verify;
}

1;
