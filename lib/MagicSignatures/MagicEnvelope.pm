#!/usr/bin/env perl

package MagicSignatures::MagicEnvelope;

# use MagicSignatures::KeyRetriever;
use MagicSignatures::MagicEnvelopeProtocol;
use MagicSignatures::Algorithms::SignatureAlgRsaSha256;
use Data::Dumper;

our $ENCODING     = 'base64url';
our $_ATOM_NS_URL = 'http://www.w3.org/2005/Atom';
our $_ME_NS_URL   = 'http://salmon-protocol.org/ns/magic-env';
our $_ATOM_NS     = "{$_ATOM_NS_URL}";
our $_ME_NS       = "{$_ME_NS_URL}";

sub new {
    my ( $class, %params ) = @_;
    my $self = { data => '', sig => '', protocol => MagicSignatures::MagicEnvelopeProtocol->new() };

    for my $field (qw(raw_data data signer_uri signer_key data_type encoding alg sig)) {
        print "$field " . $params{$field} if $params{field};
        $self->{$field} = $params{$field} if defined $params{$field};
    }
    bless( $self, $class );

    if ( $self->{raw_data} ) {    # raw data to sign

        # signing mode
        die "No data_type!" unless ( $self->{data_type} );
        die "Already have data!" if $self->{data};
        die "Already signed!"    if $self->{sig};

        my $encoded_data = $self->{protocol}->encode_data( $self->{raw_data} );
        $self->{data} = $encoded_data;
    }

    unless ( $self->{sig} ) {
        $self->sign();
    }

    return $self;
}

sub to_xml {
    my $self = shift;
    my ( $mime, $xml, $full_doc ) = @_;

    unless ( defined $full_doc ) {
        $full_doc = 1;
    }

    my $template = <<TEMPLATE;
<me:env xmlns:me='http://salmon-protocol.org/ns/magic-env'>
  <me:encoding>%s</me:encoding>
  <me:data type='application/atom+xml'>
%s
  </me:data>
  <me:alg>%s</me:alg>
  <me:sig>%s</me:sig>
</me:env>
TEMPLATE

    my $text = sprintf( $template, $self->{encoding}, $self->{data}, $self->{alg}, $self->{sig} );

    return $text;

}

sub init_from_xml { }

sub sign {
    my $self = shift;

    die "No signer URI"      unless $self->{signer_uri};
    die "No signer key!"     unless $self->{signer_key};
    die "No data to sign!"   unless $self->{raw_data} && $self->{data};
    die "Signer not allowed" unless $self->{protocol}->is_allowed_signer( $self->{raw_data}, $self->{signer_uri} );

    my $signer = MagicSignatures::Algorithms::SignatureAlgRsaSha256->new( $self->{signer_key} );
    my $sig    = $signer->sign( $self->{data} );

    $self->{sig} = $sig;
    $self->{alg} = $signer->get_name;

}

1;
