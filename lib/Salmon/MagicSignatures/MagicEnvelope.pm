#!/usr/bin/env perl

package Salmon::MagicSignatures::MagicEnvelope;

# use MagicSignatures::KeyRetriever;
use Salmon::MagicSignatures::MagicEnvelopeProtocol;
use Salmon::MagicSignatures::SignatureAlgRsaSha256;
use XML::XPath;
use XML::DOM;
use MIME::Base64::URLSafe;
use Data::Dumper;

our $ENCODING     = 'base64url';
our $_ATOM_NS_URL = 'http://www.w3.org/2005/Atom';
our $_ME_NS_URL   = 'http://salmon-protocol.org/ns/magic-env';
our $_ATOM_NS     = "atom";
our $_ME_NS       = "me";

sub new {
    my ( $class, %params ) = @_;
    my $self = { data => '', sig => '', protocol => Salmon::MagicSignatures::MagicEnvelopeProtocol->new(), };

    for my $field (qw(raw_data data signer_uri signer_key data_type encoding alg sig)) {
        print "$field " . $params{$field} if $params{field};
        $self->{$field} = $params{$field} if defined $params{$field};
    }
    bless( $self, $class );

    if ( $params{xml} ) {
        my $data = $self->data_from_xml( $params{xml} );

        for my $field (qw(data data_type encoding alg sig)) {
            $self->{$field} = $data->{$field} or die("Envelope XML did not contain required $field data!");
        }
    }

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

sub data_from_xml {
    my $self = shift;
    my ($xml) = @_;

    #    print $xml;
    # $XML::XPath::Debug = 1;
    my $xp = new XML::XPath->new( xml => $xml );

    $xp->set_namespace( $_ME_NS, $_ME_NS_URI );

    my $env_nodes = $xp->find("$_ME_NS:env");

    print "length: " . $env_nodes->size() . "\n";

    if ( !$env_nodes->size() ) {
        $env_nodes = $xp->findnodes("$_ME_NS:provenance");
    }

    unless ( $env_nodes->size() ) {
        return;
    }

    my @env_nodes = $env_nodes->get_nodelist;
    my $env_node  = $env_nodes[0];

    my $data_node = $env_node->find("$_ME_NS:data")->get_node(1);
    my $data      = _smash_whitespace( $data_node->string_value );
    print "data: $data";

    my $data_type_node = $env_node->find( "$_ME_NS:data/" . '@type' )->get_node(1);
    my $data_type      = _smash_whitespace( $data_type_node->string_value );

    my $encoding_node = $env_node->find("$_ME_NS:encoding")->get_node(1);
    my $encoding      = _smash_whitespace( $encoding_node->string_value );

    my $alg_node = $env_node->find("$_ME_NS:alg")->get_node(1);
    my $alg      = _smash_whitespace( $alg_node->string_value );

    my $sig_node = $env_node->find("$_ME_NS:sig")->get_node(1);
    my $sig      = _smash_whitespace( $sig_node->string_value );
    print "sig: $sig";

    my $ret_data = { data => $data, data_type => $data_type, encoding => $encoding, alg => $alg, sig => $sig };
    return $ret_data;
}

sub to_xml {
    my $self = shift;
    my ($full_doc) = @_;

    unless ( defined $full_doc ) {
        $full_doc = 1;
    }

    my $template = ( $full_doc ? "<?xml version='1.0' ?>\n" : '' );
    $template .= <<TEMPLATE;
<me:env xmlns:me='http://salmon-protocol.org/ns/magic-env'>
  <me:encoding>%s</me:encoding>
  <me:data type='application/atom+xml'>
%s
  </me:data>
  <me:alg>%s</me:alg>
  <me:sig>
%s
  </me:sig>
</me:env>
TEMPLATE

    my $text = sprintf( $template,
        $self->{encoding}, $self->_to_pretty( $self->{data}, 4, 60 ),
        $self->{alg},      $self->_to_pretty( $self->{sig},  4, 60 ) );

    return $text;

}

sub sign {
    my $self = shift;

    die " No signer URI "    unless $self->{signer_uri};
    die " No signer key !"   unless $self->{signer_key};
    die " No data to sign !" unless $self->{raw_data} && $self->{data};
    die " Signer not allowed
        " unless $self->{protocol}->is_allowed_signer( $self->{raw_data}, $self->{signer_uri} );

    my $signer = Salmon::MagicSignatures::SignatureAlgRsaSha256->new( $self->{signer_key} );
    my $sig    = $signer->sign( $self->{data} );

    $self->{sig} = $sig;
    $self->{alg} = $signer->get_name;

}

sub unfold {
    my $self   = shift;
    my $parser = new XML::DOM::Parser;
    print urlsafe_b64decode( $self->{data} );
    my $dom = $parser->parse( urlsafe_b64decode( $self->{data} ) );

    my $prov = $dom->createElement("$_ME_NS:provenance");
    $prov->setAttribute( 'xmlns:me', $_ME_NS_URL );

    my $data = $dom->createElement("$_ME_NS:data");
    $data->appendChild( $dom->createTextNode( $self->{data} ) );
    $data->setAttribute( 'type', $self->{data_type} );
    $prov->appendChild($data);

    for my $field (qw(encoding sig alg)) {
        my $field_el = $dom->createElement("$_ME_NS:$field");
        $field_el->appendChild( $dom->createTextNode( $self->{$field} ) );
        $prov->appendChild($field_el);
    }
    $dom->getDocumentElement->appendChild($prov);

    my $atom = $dom->toString;
    $dom->dispose;

    return $atom;
}

sub _to_pretty {
    my $self = shift;
    my ( $text, $indent, $linelength ) = @_;
    $tl     = $linelength - $indent;
    $output = '';
    for my $i ( 0 .. ( ( length $text ) / $tl ) ) {
        $output .= " \n " if $output;
        $output .= ( ' ' x $indent ) . substr $text, $i * $tl, $tl;
    }

    return $output;
}

sub _smash_whitespace {
    my $input = shift;
    $input =~ s/[\s]*//xmsg;
    return $input;
}

1;
