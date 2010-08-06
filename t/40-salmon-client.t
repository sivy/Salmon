#!/usr/bin/env perl
# 10-magic-envelopes.t
use lib qw(../lib);

use strict;
use warnings;

use Carp::Always;

use Test::More qw (no_plan);

use Crypt::RSA;
use Salmon::Client;
use Salmon::MagicSignatures::SignatureAlgRsaSha256;

my $endpoint = 'http://monkinetic.status.net/main/salmon/user/1';

my $author = 'steveivy@atollia.appspot.com';

my $xrd = 'http://monkinetic.status.net/main/xrd?steveivy@monkinetic.status.net';

# setup keys (one time only for testing)
# my $rsa = new Crypt::RSA( ES => 'PKCS1v15', SS => { Module => 'Salmon::Crypt::RSA::SS::PKCS1v15_SHA256' } );
# my ( $gen_public, $gen_private ) = $rsa->keygen(
#     Identity  => 'Steve Ivy <steveivy@atollia.appspot.com>',
#     Size      => 1024,
#     Password  => 'test',
#     Verbosity => 1,
# ) or die $rsa->errstr();

# my $signer = Salmon::MagicSignatures::SignatureAlgRsaSha256->new( $gen_private, 1 );

my $private_key_str =
    "RSA.hDq_qUbQAbcU1nY4si3CLS91WGsNuXkB4tor0wHI0pvFYKG81Sr7Y19z_-1RO2blKIxSGHfRo0OFcDNlfRVSmH6Kczk_tVvNzerjeypx-8AN5QiBrZEhi7IU88sJ1wcY0LWHdvboS-WFJuSZmMIdAZRiz7aExQgHzgkuBQfzjRs=.AQAB.YGRvWZg8hDORpjFybTl8RvJEydrom1-CJ3xB3EV9v0I85Y-iF4eI0M1Bw7ydrf75aNC5_ApEsY7EVKGzBzcnCOTz7CgVUuM05hwL4E-L_Ah0ZDl1Lz_esL4ZB5mCIALpLw8b8VkyrOaHD1sn_z2LB4ArW3zr6qF4Ps32v6ODWgk=";

# $signer->to_string(1);
# diag "private key: " . $private_key_str;

my $public_key_str =
    "RSA.hDq_qUbQAbcU1nY4si3CLS91WGsNuXkB4tor0wHI0pvFYKG81Sr7Y19z_-1RO2blKIxSGHfRo0OFcDNlfRVSmH6Kczk_tVvNzerjeypx-8AN5QiBrZEhi7IU88sJ1wcY0LWHdvboS-WFJuSZmMIdAZRiz7aExQgHzgkuBQfzjRs=.AQAB";

my $signer = Salmon::MagicSignatures::SignatureAlgRsaSha256->new($private_key_str);

# $signer->to_string(0);
# diag "public key: " . $public_key_str;
# done with keys

# ok( $rsa, 'Crypt::RSA created' );

my $fishy = new Salmon::Client;

my $id = rand;

use DateTime;
my $dt  = DateTime->now;
my $now = $dt->ymd . 'T' . $dt->hms . 'Z';

my $slap = <<SLAP;
<?xml version='1.0' encoding='UTF-8'?>
<entry xmlns='http://www.w3.org/2005/Atom'>
  <activity:actor>
    <activity:object-type>http://activitystrea.ms/schema/1.0/person</activity:object-type>
    <id>http://monkinetic.status.net/user/1</id>
	<title>Steve Ivy</title>
	<link rel="alternate" type="text/html" href="http://monkinetic.status.net/"/>
	<link rel="avatar" type="image/png" media:width="96" media:height="96" href="http://avatar.status.net/monkinetic/1-96-20100222001150.png"/>
	<link rel="avatar" type="image/png" media:width="96" media:height="96" href="http://avatar.status.net/monkinetic/1-96-20100222001150.png"/>
	<link rel="avatar" type="image/png" media:width="48" media:height="48" href="http://avatar.status.net/monkinetic/1-48-20100222001150.png"/>
	<link rel="avatar" type="image/png" media:width="24" media:height="24" href="http://avatar.status.net/monkinetic/1-24-20100222001150.png"/>
	</activity:actor>
    <id>tag:example.com,2010-$id</id>
    <author><name>$author</name><uri>$author</uri></author>
    <thr:in-reply-to xmlns:thr='http://purl.org/syndication/thread/1.0'
         ref='http://monkinetic.status.net/notice/13'>
	http://monkinetic.status.net/notice/13
    </thr:in-reply-to>
    <content>Salmon swim upstream!</content>
    <title>Salmon swim upstream!</title>
    <updated>$now</updated>
  </entry>
SLAP

diag $slap;

# $fishy->post( $endpoint, $slap, $author, $private_key_str );

my $env = Salmon::MagicSignatures::MagicEnvelope->new(
    raw_data   => $slap,                     #data to sign
    signer_uri => $author,                   #sign with this user's priv key
    signer_key => $private_key_str,
    data_type  => 'application/atom+xml',    # MIME of the content
    encoding   => 'base64url',               # encoder
    alg        => 'RSA-SHA256',              # sig algorithm
);

my $env_xml = $env->to_xml;

# create http client
use LWP::UserAgent;
my $ua = LWP::UserAgent->new;

my $req = HTTP::Request->new( POST => $endpoint );

# setup headers
$req->content_type('application/magic-envelope+xml');
$req->content($slap);

# post the message
my $res = $ua->request($req);
print $res->as_string;
