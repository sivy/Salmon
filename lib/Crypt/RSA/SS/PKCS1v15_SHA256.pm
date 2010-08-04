#!/usr/bin/env perl

package Crypt::RSA::SS::PKCS1v15_SHA256;
use Carp;
use strict;
use warnings;

use Digest::SHA qw(sha256 sha256_hex);
use Crypt::RSA::DataFormat qw(h2osp);

use base qw(Crypt::RSA::SS::PKCS1v15);

sub new {
    my ( $class, %params ) = @_;
    my $self = $class->SUPER::new(%params);
    $self->{encoding}->{SHA256} = "0x 30 31 30 0d 06 09 60 86 48 01
                                      65 03 04 02 01 05 00 04 20";
    $self->{digest} = 'SHA256';

    if ( $params{Version} ) {

        # do versioning here
    }
    return $self;

}

sub encode {
    my ( $self, $M, $emlen ) = @_;

    # Let hash = the SHA256 hash digest of M
    my $H = sha256($M);

# Let prefix = the constant byte sequence: [0x30, 0x31, 0x30, 0xd, 0x6, 0x9, 0x60, 0x86, 0x48, 0x1, 0x65, 0x3, 0x4, 0x2, 0x1, 0x5, 0x0, 0x4, 0x20]
    my $alg = h2osp( $self->{encoding}->{ $self->{digest} } );

    my $T = $alg . $H;

    $self->error( "Intended encoded message length too short.", \$M ) if $emlen < length($T) + 10;

    # Let k = the number of bytes in the public key modulus
    # Let padding = '\xFF' repeated (k - length(prefix+hash) - 3) times
    my $pslen = $emlen - length($T) - 2;
    my $PS    = chr(0xff) x $pslen;

    my $em = chr(1) . $PS . chr(0) . $T;
    return $em;
}

1;
