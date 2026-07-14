#!perl
use strict;
use warnings;

# Parser-abuse / robustness tests for App::Nisaba::WebSelfService, in-process via
# Test::Mojo (mocked pt, same shape as t/web-selfservice.t). Malformed input on
# the public and authenticated surfaces — login, TOTP codes, the forgot form, the
# password-reset token (base64 + null-delimited + HMAC), SSH keys, passkey JSON —
# must be handled gracefully (a clean 3xx/4xx), never an uncaught exception (500),
# and must not hang (each request runs under a signal alarm, catching a
# pathological-regex/ReDoS regression that would block the event loop).
#
# The self-service app has no user-supplied redirect target (all redirects are
# hardcoded route names), so no open-redirect / response-splitting test applies.

use File::Basename ();
use File::Spec;

BEGIN {
	my $share
		= File::Spec->rel2abs( File::Spec->catdir( File::Basename::dirname(__FILE__), File::Spec->updir, 'share' ) );
	require File::ShareDir;
	no warnings 'redefine';
	*File::ShareDir::dist_dir = sub { $share };

	$ENV{NISABA_SECRET}        = 'test-secret-nisaba' unless defined $ENV{NISABA_SECRET};
	$ENV{NISABA_COOKIE_SECURE} = '0'                  unless defined $ENV{NISABA_COOKIE_SECURE};
	$ENV{NISABA_RATELIMIT}     = '0'                  unless defined $ENV{NISABA_RATELIMIT};
} ## end BEGIN

use Test::More;
use Mojo::Util ();

eval { require App::Nisaba::WebSelfService; 1 }
	or plan skip_all => "App::Nisaba::WebSelfService failed to load: $@";
eval { require Test::Mojo; 1 } or plan skip_all => "Test::Mojo unavailable: $@";
plan skip_all => 'alarm() not available on this platform'
	unless eval {
		local $SIG{ALRM} = sub { };
		alarm(0);
		1;
	};

{

	package FakeEntry;
	sub new { my ( $c, %a ) = @_; return bless { attrs => \%a }, $c }

	sub get_value {
		my ( $self, $attr ) = @_;
		my $v = $self->{attrs}{$attr};
		return () unless defined $v;
		return wantarray ? ( ref $v ? @{$v} : ($v) ) : ( ref $v ? $v->[0] : $v );
	}
}

sub install_stubs {
	my ($app) = @_;
	my %methods = (
		error       => sub { 0 },
		errorString => sub { '' },
		errorblank  => sub { },

		userVerifyPassword => sub {
			my ( $s, $a ) = @_;
			die "bad password\n"
				unless ( $a->{user} // '' ) eq 'alice' && ( $a->{password} // '' ) eq 'correct';
			return 1;
		},
		userSelfInfo    => sub { return { mail => 'alice@example.com', totpStatus => 'inactive' } },
		userTotpVerify  => sub { return 0 },
		getUserEntry    => sub { return FakeEntry->new( userPassword => '{SSHA}ORIGINAL' ) },
		userSetPassSelf => sub { return 1 },

		smtpAvailable           => sub { 1 },
		sendEmail               => sub { return 1 },
		userSSHPublicKeyAddSelf => sub { return 1 },

		ldapPublicKeyAvailable => sub { 1 },
		totpSchemaAvailable    => sub { 1 },
		passkeySchemaAvailable => sub { 0 },
		userPasskeyInfoGet     => sub { { hasPasskeyUser => 0, credentials => [] } },
	);
	my $fake = bless { ini => { '' => {} } }, 'FakePT';
	Mojo::Util::monkey_patch( 'FakePT', %methods );
	$app->helper( pt => sub { $fake } );
	return;
} ## end sub install_stubs

my $t = Test::Mojo->new('App::Nisaba::WebSelfService');
install_stubs( $t->app );
$t->ua->on(
	start => sub {
		my ( $ua, $tx ) = @_;
		return unless $tx->req->method eq 'POST';
		my $host = $tx->req->url->to_abs->host_port // 'localhost';
		$tx->req->headers->referrer("http://$host/");
		$tx->req->headers->header( 'X-CSRF-Token' => 'testcsrf' );
	}
);
$t->app->hook( before_dispatch => sub { $_[0]->session( csrf_token => 'testcsrf', user => 'alice' ) } );

my $BUDGET = 8;

sub probe {
	my ( $desc, $fn ) = @_;
	my $tx;
	my $ok = eval {
		local $SIG{ALRM} = sub { die "timeout\n" };
		alarm($BUDGET);
		$tx = $fn->();
		alarm(0);
		1;
	};
	alarm(0);
	if ( !$ok ) { ok( 0, "$desc: did NOT complete within ${BUDGET}s — possible ReDoS/hang" ); return }
	my $code = $tx ? $tx->res->code : undef;
	ok( defined $code && $code != 500, "$desc: handled cleanly (HTTP " . ( defined $code ? $code : '?' ) . ')' );
	return;
} ## end sub probe

my $huge = 'A' x 100_000;
my $ctrl = "a\x00\x01\x02\x1f";

# ── Login / TOTP / forgot ────────────────────────────────────────────────────
probe( 'login: control bytes in user', sub { $t->ua->post( '/login', form => { user => $ctrl, pass => $ctrl } ) } );
probe( 'login: oversized credentials', sub { $t->ua->post( '/login', form => { user => $huge, pass => $huge } ) } );
probe( 'totp challenge: empty code',   sub { $t->ua->post( '/totp/challenge', form => { code => '' } ) } );
probe( 'totp challenge: non-digit code',
	sub { $t->ua->post( '/totp/challenge', form => { code => 'not-a-code!!' } ) } );
probe( 'totp challenge: oversized code',         sub { $t->ua->post( '/totp/challenge', form => { code => $huge } ) } );
probe( 'forgot: control bytes + oversized user', sub { $t->ua->post( '/forgot', form => { user => "$ctrl$huge" } ) } );

# ── Password-reset token abuse ───────────────────────────────────────────────
for my $tok ( 'AAAA', 'not!base64', 'a', ( 'Z' x 100_000 ), '---,,,', 'deadbeef.cafe' ) {
	probe(
		"reset: malformed token '"
			. ( length($tok) > 16 ? substr( $tok, 0, 16 ) . "...(" . length($tok) . ')' : $tok ) . "'",
		sub { $t->ua->post( "/reset/$tok", form => { new_pass => 'x', confirm => 'x' } ) }
	);
}

# ── Authenticated surfaces ───────────────────────────────────────────────────
probe( 'password change: oversized fields',
	sub { $t->ua->post( '/password', form => { current => $huge, new_pass => $huge, confirm => $huge } ) } );
probe( 'sshkey add: control bytes + oversized key',
	sub { $t->ua->post( '/sshkeys/add', form => { key => "$ctrl$huge" } ) } );
probe( 'passkey finish: malformed JSON body',
	sub { $t->ua->post( '/passkeys/login/finish', { 'Content-Type' => 'application/json' }, '{"id":"x",' ) } );

done_testing;
