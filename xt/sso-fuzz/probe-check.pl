#!/usr/bin/env perl

# probe-check.pl — a standalone smoke test of the SSO abuse checks, run with
# Mojo::UserAgent (already a dependency) against a live sso-fuzz target. Each
# check mirrors one of the assertions in xt/sso-fuzz.t (open redirect, LDAP
# injection, parser abuse, header injection); use it for a quick "is this target
# secure?" check outside the test harness.
#
# Each check prints PASS (secure / handled) or FAIL (a real defect). Exit is
# non-zero if any check FAILs.
#
#   perl xt/sso-fuzz/probe-check.pl --port 3000
#   perl xt/sso-fuzz/probe-check.pl --host 127.0.0.1 --port 3000 --client pub

use strict;
use warnings;
use Getopt::Long    qw(:config no_ignore_case bundling);
use Mojo::UserAgent ();
use Mojo::URL       ();
use Digest::SHA     qw(sha256);
use MIME::Base64    qw(encode_base64url);

my %opt = ( host => '127.0.0.1', port => 3000, client => 'pub', evil => 'evil.attacker.example' );
GetOptions( \%opt, 'host=s', 'port=i', 'client=s', 'redirect=s', 'evil=s', 'help|h' )
	or die "bad options\n";
if ( $opt{help} ) { print "usage: probe-check.pl --host H --port P [--client ID --redirect URI]\n"; exit 0 }
$opt{redirect} //= 'https://fuzz.example.com/pub-callback';

my $base = "http://$opt{host}:$opt{port}";
my $ua   = Mojo::UserAgent->new( max_redirects => 0 );
$ua->connect_timeout(5)->request_timeout(15);
my ( $pass, $fail ) = ( 0, 0 );

sub ok  { my ($m) = @_; print "  PASS  $m\n"; $pass++; return }
sub bad { my ($m) = @_; print "  FAIL  $m\n"; $fail++; return }

sub pkce {
	my $v = 'verifier-1234567890-abcdefghij';
	return encode_base64url( sha256($v) );
}

sub authz {
	my (%o) = @_;
	my $url = Mojo::URL->new("$base/authorize")->query(
		{
			response_type         => 'code',
			client_id             => $opt{client},
			redirect_uri          => $opt{redirect},
			scope                 => 'openid',
			state                 => 'st123',
			nonce                 => 'nn123',
			code_challenge        => pkce(),
			code_challenge_method => 'S256',
			%o,
		}
	);
	return $ua->get($url);
} ## end sub authz

sub reached_ui {
	my ($tx) = @_;
	my $loc = $tx->res->headers->location // '';
	return 1 if $loc                                                       =~ m{/sso/(?:login|consent|totp)};
	return 1 if ( $tx->res->code // 0 ) == 200 && ( $tx->res->body // '' ) =~ /name=["']?(?:user|pass)/i;
	return 0;
}

print "== discovery ==\n";
my $d = $ua->get("$base/.well-known/openid-configuration");
( ( $d->res->code // 0 ) == 200 && ( $d->res->json('/issuer') // '' ) ne '' )
	? ok( 'discovery 200 issuer=' . $d->res->json('/issuer') )
	: bad('discovery did not return a valid document');

print "== baseline: a valid authorize request reaches the login UI ==\n";
my $good = authz();
reached_ui($good)
	? ok( "client_id=$opt{client} reached the UI (code "
		. ( $good->res->code // '?' )
		. ', loc '
		. ( $good->res->headers->location // '-' )
		. ')' )
	: bad( 'valid client did not reach the UI (code ' . ( $good->res->code // '?' ) . ')' );

print "== open redirect: unregistered redirect_uri must NOT 3xx to the attacker host ==\n";
for my $p ( "https://$opt{evil}/", "$opt{redirect}.$opt{evil}", "//$opt{evil}/" ) {
	my $tx  = authz( redirect_uri => $p );
	my $loc = $tx->res->headers->location // '';
	my $c   = $tx->res->code              // 0;
	( $c >= 300 && $c < 400 && $loc =~ /\Q$opt{evil}\E/ )
		? bad("OPEN REDIRECT: $p -> $loc")
		: ok("rejected redirect_uri=$p (code $c)");
}

print "== LDAP injection: filter metacharacters in client_id must not match a client ==\n";
my $rnd = authz( client_id => 'zzznope' . int( rand 1e6 ) );
if ( reached_ui($rnd) ) {
	print "  SKIP  unknown client_id already reaches the UI; check inconclusive\n";
} else {
	for my $inj ( '*', "$opt{client}*", '*)(oidcClientId=*' ) {
		my $tx = authz( client_id => $inj );
		reached_ui($tx)
			? bad("LDAP INJECTION: client_id=$inj matched a client")
			: ok( "client_id=$inj did not match (code " . ( $tx->res->code // '?' ) . ')' );
	}
}

print "== parser abuse: malformed input must be handled (no 500 / no dropped connection) ==\n";
my @cases = (
	[
		'passkey truncated json',
		sub {
			$ua->post(
				"$base/sso/passkeys/login/finish" => { 'Content-Type' => 'application/json' } => '{"id":"x",' );
		}
	],
	[
		'passkey not-a-hash',
		sub {
			$ua->post( "$base/sso/passkeys/login/finish" => { 'Content-Type' => 'application/json' } =>
					'{"response":"notahash"}' );
		}
	],
	[
		'passkey garbage',
		sub {
			$ua->post(
				"$base/sso/passkeys/login/finish" => { 'Content-Type' => 'application/json' } => '%%%not-json%%%' );
		}
	],
	[
		'token malformed basic',
		sub {
			$ua->post( "$base/token" => { 'Authorization' => 'Basic !!!not-base64' } => form =>
					{ grant_type => 'authorization_code', code => 'abcd' } );
		}
	],
	[
		'logout bad id_token_hint',
		sub { $ua->get( Mojo::URL->new("$base/sso/logout")->query( { id_token_hint => '..%20.' } ) ) }
	],
	[ 'authorize oversized scope', sub { authz( scope => 'openid ' . ( 'A' x 200_000 ) ) } ],
);
for my $c (@cases) {
	my ( $label, $fn ) = @{$c};
	my $tx = eval { $fn->() };
	if    ( !$tx || !$tx->res->code ) { bad("PARSER: '$label' produced no response / dropped connection") }
	elsif ( $tx->res->code == 500 )   { bad("PARSER: '$label' returned HTTP 500") }
	else                              { ok( "'$label' handled (code " . $tx->res->code . ')' ) }
}

print "== header injection: a CRLF payload must NOT split into a new response header ==\n";
my $marker = 'X-Nisaba-Inject-' . int( rand 1e6 );
my $tx     = authz( scope => 'openid bogus_unregistered', state => "s\r\n$marker: pwned" );
# Only a genuine split creates a header NAMED $marker; the marker appearing inside
# a URL-encoded Location value (reflected state) is not a vuln.
my $split = grep { lc eq lc $marker } @{ $tx->res->headers->names };
$split
	? bad("HEADER INJECTION: server split the payload into a '$marker' header")
	: ok( 'no CRLF header split (code ' . ( $tx->res->code // '?' ) . ')' );

print "\n== RESULT: pass=$pass fail=$fail ==\n";
exit( $fail ? 1 : 0 );
