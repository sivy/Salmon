#!/usr/bin/env perl

package Salmon::MagicSignatures::SignatureAlgRsaSha256;

use strict;
use warnings;

use Crypt::RSA;
use Crypt::RSA::DataFormat qw(h2osp i2osp);
use Crypt::RSA::Key::Private;
use MIME::Base64::URLSafe;
use Data::Dumper;

sub new {
    my $class = shift;
    my ($key) = @_;

    my $self = { private => 0 };
    bless( $self, $class );

    return $self unless $key;

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

    my $type = 'RSA';
    my $mod  = $self->_encode_b64( $self->{key}->n );
    my $exp  = $self->_encode_b64( $self->{key}->e );
    my $private_exp;
    $private_exp = $self->_encode_b64( $self->{key}->d )
        if ( $full_key_pair && $self->{private} && $self->{key}->d );

    return "$type.$mod.$exp" . ( $private_exp ? ".$private_exp" : '' );
}

sub init_from_string {
    my $self = shift;
    my ($key_str) = @_;
    my $key;
    my ( $type, $mod, $exp, $private_exp ) = split /\./, $key_str;
    if ( $type ne 'RSA' || !defined($mod) || !defined($exp) ) {
        die "Unknown key format";
    }
    if ($private_exp) {
        $key = new Crypt::RSA::Key::Private;
        $self->{private} = 1;
    }
    else {
        $key = new Crypt::RSA::Key::Public;
    }
    $_ = $self->_decode_b64($_) for $mod, $exp;

    $key->n($mod);
    $key->e($exp);

    if ($private_exp) {
        $private_exp = $self->_decode_b64($private_exp);
    }
    $key->d($private_exp) if ( $self->{private} && $private_exp );
    $key->{Checked} = 1;

    $self->{key} = $key;
}

sub sign {
    my $self = shift;
    my ($bytes_to_sign) = @_;
    my $rsa = new Crypt::RSA( ES => 'PKCS1v15', SS => { Module => 'Salmon::Crypt::RSA::SS::PKCS1v15_SHA256' } );

    my $signature = $rsa->sign(
        Key     => $self->{key},
        Message => $bytes_to_sign,
    ) or die $rsa->errstr;

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

    my $rsa = new Crypt::RSA( ES => 'PKCS1v15', SS => { Module => 'Crypt::RSA::SS::PKCS1v15_SHA256' } );
    my $verify = $rsa->verify(
        Message   => $signed_bytes,
        Signature => $decoded_sig,
        Key       => $self->{key},
    );
    return $verify;
}

sub _decode_b64 {
    my ( $self, $encoded ) = @_;
    my $data = MIME::Base64::URLSafe::decode($encoded);
    my $hex  = "0x" . unpack "H*", $data;
    my $bstr = Math::BigInt->from_hex($hex)->bstr;

    # print "encoded: $encoded\nhex: $hex\nbstr: $bstr\n\n";
    return $bstr;
}

sub _encode_b64 {
    my ( $self, $val ) = @_;
    my ( $bigint, $hex );

    $bigint = Math::BigInt->new($val);
    $hex    = $bigint->as_hex;

    # print "pre-tweaked hex: $hex\n";
    $hex =~ s/^0x//;
    $hex = ( ( length $hex ) % 2 > 0 ) ? "0$hex" : $hex;
    my $data = pack "H*", $hex;
    my $encoded = MIME::Base64::URLSafe::encode($data);
    while ( ( length $encoded ) % 4 != 0 ) {
        $encoded .= chr(61);
    }

    # print "bstr: $val\nhex: $hex\nencoded: $encoded\n\n";
    return $encoded;
}

1;
