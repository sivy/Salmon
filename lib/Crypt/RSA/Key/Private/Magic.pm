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

sub to_string {
    my $self = shift;

    my ($full_key_pair) = @_;
    unless ( defined $full_key_pair ) {
        $full_key_pair = 1;
    }

    my $type = 'RSA';
    my $mod  = $self->_encode_b64( $self->n );
    my $exp  = $self->_encode_b64( $self->e );
    my $private_exp;
    $private_exp = $self->_encode_b64( $self->d ) if $self->d;

    return "$type.$mod.$exp" . ( $private_exp ? ".$private_exp" : '' );
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
