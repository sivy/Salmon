#!/usr/bin/env perl

package Crypt::RSA::SS::PKCS1v15::PKCS1v15_SHA256;

use strict;
use warnings;

use Digest::SHA qw(sha256 sha256_hex);

use base qw(Crypt::RSA::SS::PKCS1v15);

sub new {

    my ( $class, %params ) = @_;

    # $self = bless {
    #                    primitives => new Crypt::RSA::Primitives,
    #                    digest     => $params{Digest} || 'SHA1',
    #                    encoding   => {
    #                                     MD2 => "0x 30 20 30 0C 06 08 2A 86 48
    #                                                86 F7 0D 02 02 05 00 04 10",
    #                                     MD5 => "0x 30 20 30 0C 06 08 2A 86 48
    #                                                86 F7 0D 02 05 05 00 04 10",
    #                                    SHA1 => "0x 30 21 30 09 06 05 2B 0E 03
    #                                                02 1A 05 00 04 14",
    #                                  },
    #                    VERSION    => $Crypt::RSA::SS::PKCS1v15::VERSION,
    #                  }, $class;

    my $self = $class->SUPER::new(@_);
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

    my $H = sha256($M);

    my $alg = h2osp( $self->{encoding}->{ $self->{digest} } );
    my $T   = $alg . $H;
    $self->error( "Intended encoded message length too short.", \$M ) if $emlen < length($T) + 10;
    my $pslen = $emlen - length($T) - 2;
    my $PS    = chr(0xff) x $pslen;
    my $em    = chr(1) . $PS . chr(0) . $T;
    return $em;

}

1;
