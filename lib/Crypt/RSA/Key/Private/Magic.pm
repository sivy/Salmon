package Crypt::RSA::Key::Private::Magic;
use strict;
use warnings;
use MIME::Base64::URLSafe ();
use Math::BigInt;

use base 'Crypt::RSA::Key::Private';

sub from_string {
    my ( $class, $string ) = @_;

    my $self = $class->new;

    my ( $type, $mod, $exp, $private_exp ) = split /\./, $string;
    if ( $type ne 'RSA' || !defined($mod) || !defined($exp) || !defined($private_exp) ) {
        die "Unknown key format";
    }

    $_ = $self->_decode_b64($_) for $mod, $exp, $private_exp;

    $self->n($mod);
    $self->e($exp);
    $self->d($private_exp);
    $self->{Checked} = 1;

    return $self;
}

sub _decode_b64 {
    my ( $self, $val ) = @_;

    my $decoded = MIME::Base64::URLSafe::decode($val);
    my $hex = "0x" . unpack "H*", $decoded;
    return Math::BigInt->from_hex($hex)->bstr;
}

1;
