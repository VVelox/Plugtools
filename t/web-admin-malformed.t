#!perl
use strict;
use warnings;

# Parser-abuse / robustness tests for the App::Nisaba::Web admin UI, in-process
# via Test::Mojo (mocked pt, same shape as t/web-users.t). Malformed input on the
# public surfaces (login, TOTP code, passkey JSON) and the authenticated CRUD
# surfaces (numeric uid/gid coercion, multiline netgroup triples and OIDC
# redirect-URI parsing) must be handled gracefully — a clean 3xx/4xx, never an
# uncaught exception (500) — and must not hang (each request runs under a signal
# alarm to catch a ReDoS regression that would block the event loop).
#
# The admin app has no user-supplied redirect target (all redirects are hardcoded
# route names), so no open-redirect / response-splitting test applies.

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

eval { require App::Nisaba::Web; 1 } or plan skip_all => "App::Nisaba::Web failed to load: $@";
eval { require Test::Mojo;       1 } or plan skip_all => "Test::Mojo unavailable: $@";
plan skip_all => 'alarm() not available on this platform'
	unless eval {
		local $SIG{ALRM} = sub { };
		alarm(0);
		1;
	};

{

	package FakeEntry;

	sub new {
		my ( $class, %attrs ) = @_;
		return bless { attrs => \%attrs, _dn => delete $attrs{_dn} // '' }, $class;
	}
	sub dn         { return $_[0]->{_dn} }
	sub attributes { return keys %{ $_[0]->{attrs} } }

	sub get_value {
		my ( $self, $attr ) = @_;
		my $v = $self->{attrs}{$attr};
		return () unless defined $v;
		return wantarray ? ( ref $v ? @{$v} : ($v) ) : ( ref $v ? $v->[0] : $v );
	}
}

my $usr_alice = FakeEntry->new(
	_dn           => 'uid=alice,ou=users,dc=example,dc=com',
	uid           => 'alice',
	uidNumber     => '1000',
	gidNumber     => '1000',
	homeDirectory => '/home/alice',
	loginShell    => '/bin/bash',
	gecos         => 'Alice A',
	objectClass   => [ 'posixAccount', 'inetOrgPerson', 'person' ],
	cn            => ['Alice A'],
	sn            => 'A',
	mail          => ['alice@example.com'],
);
my $grp_admins = FakeEntry->new(
	_dn       => 'cn=admins,ou=groups,dc=example,dc=com',
	cn        => 'admins',
	gidNumber => '1000',
	memberUid => ['alice'],
);

# Full pt stub set (mirrors t/web-users.t) so that a well-formed request would
# succeed — a malformed one then exercises the real parsing/validation code.
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
		userSelfInfo => sub { return { totpStatus => 'inactive' } },

		getUsers                    => sub { [$usr_alice] },
		getGroups                   => sub { [$grp_admins] },
		getUserEntry                => sub { $usr_alice },
		findGroupDN                 => sub { 'cn=admins,ou=groups,dc=example,dc=com' },
		isLDAPgroup                 => sub { 1 },
		addUser                     => sub { },
		deleteUser                  => sub { },
		addGroup                    => sub { },
		deleteGroup                 => sub { },
		addNetgroup                 => sub { },
		deleteNetgroup              => sub { },
		getNetgroups                => sub { [] },
		getNetgroupEntry            => sub { undef },
		addOIDCClient               => sub { },
		getOIDCClients              => sub { [] },
		getOIDCClientEntry          => sub { undef },
		userHasPassword             => sub { 1 },
		userSetPass                 => sub { },
		userRemovePassword          => sub { },
		userGECOSchange             => sub { },
		userShellChange             => sub { },
		userUIDchange               => sub { },
		userGIDchange               => sub { },
		userHomeChange              => sub { },
		userTitleChange             => sub { },
		userRoomNumberChange        => sub { },
		userEmployeeNumberChange    => sub { },
		userEmployeeTypeChange      => sub { },
		userMailAdd                 => sub { },
		userMailRemove              => sub { },
		userTelephoneNumberAdd      => sub { },
		userTelephoneNumberRemove   => sub { },
		userMobileAdd               => sub { },
		userMobileRemove            => sub { },
		userPreferredLanguageAdd    => sub { },
		userPreferredLanguageRemove => sub { },
		userLabeledURIAdd           => sub { },
		userLabeledURIRemove        => sub { },
		userSNchange                => sub { },
		userGivenNameChange         => sub { },
		userDisplayNameChange       => sub { },
		userHomePostalAddressChange => sub { },
		userDescriptionAdd          => sub { },
		userDescriptionRemove       => sub { },
		userPostalAddressAdd        => sub { },
		userPostalAddressRemove     => sub { },
		userCNadd                   => sub { },
		userCNremove                => sub { },
		userSSHPublicKeyAdd         => sub { },
		userSSHPublicKeyRemove      => sub { },
		userConvertToInetOrgPerson  => sub { },
		userConvertToLdapPublicKey  => sub { },
		userConvertToTotp           => sub { },
		userConvertToPasskeyUser    => sub { },
		userTotpGenerateSecret      => sub { 'JBSWY3DPEHPK3PXP' },
		userTotpVerify              => sub { 0 },
		userTotpStatusSet           => sub { },
		userTotpInfoGet             => sub { { totpStatus  => 'active', totpScratchCodes => [] } },
		userPasskeyInfoGet          => sub { { credentials => [] } },
		groupAddUser                => sub { },
		groupRemoveUser             => sub { },
		groupGIDchange              => sub { },
		groupDescriptionChange      => sub { },
		ldapPublicKeyAvailable      => sub { 1 },
		totpSchemaAvailable         => sub { 1 },
		passkeySchemaAvailable      => sub { 1 },
		netgroupbaseConfigured      => sub { 1 },
		oidcbaseConfigured          => sub { 1 },
	);
	my $fake_pt = bless { ini => { '' => { totpAdminAddScratchCodes => 0 } } }, 'FakePT';
	Mojo::Util::monkey_patch( 'FakePT', %methods );
	$app->helper( pt => sub { $fake_pt } );
	return;
} ## end sub install_stubs

my $t = Test::Mojo->new('App::Nisaba::Web');
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
$t->app->hook( before_dispatch => sub { $_[0]->session( admin_user => 'testadmin', csrf_token => 'testcsrf' ) } );

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

# ── Public surfaces ──────────────────────────────────────────────────────────
probe( 'login: control bytes',           sub { $t->ua->post( '/login', form => { user => $ctrl, pass => $ctrl } ) } );
probe( 'login: oversized',               sub { $t->ua->post( '/login', form => { user => $huge, pass => $huge } ) } );
probe( 'totp challenge: empty code',     sub { $t->ua->post( '/totp/challenge', form => { code => '' } ) } );
probe( 'totp challenge: non-digit code', sub { $t->ua->post( '/totp/challenge', form => { code => 'nope!!' } ) } );
probe( 'totp challenge: oversized code', sub { $t->ua->post( '/totp/challenge', form => { code => $huge } ) } );
probe( 'passkey finish: malformed JSON',
	sub { $t->ua->post( '/passkeys/login/finish', { 'Content-Type' => 'application/json' }, '{"id":' ) } );

# ── Authenticated CRUD: numeric coercion ─────────────────────────────────────
probe( 'user create: negative uid',
	sub { $t->ua->post( '/users', form => { user => 'x', uid => '-5', group => 'g' } ) } );
probe( 'user create: non-numeric uid/gid',
	sub { $t->ua->post( '/users', form => { user => 'x', uid => 'abc', gid => 'xyz' } ) } );
probe( 'user create: oversized uid + control-byte name',
	sub { $t->ua->post( '/users', form => { user => $ctrl, uid => ( '9' x 40 ) } ) } );
probe( 'user update: junk action',
	sub { $t->ua->post( '/users/alice', form => { action => "\x00garbage", value => $ctrl } ) } );
probe( 'group create: non-numeric gid', sub { $t->ua->post( '/groups', form => { group => 'g', gid => 'notnum' } ) } );

# ── Authenticated CRUD: multiline / URI parsing ──────────────────────────────
probe(
	'netgroup create: malformed multiline triples + members',
	sub {
		$t->ua->post( '/netgroups',
			form => { group => 'ng', triple => "(\r\n)(\r\n$ctrl\r\n", member => "$ctrl\r\n$huge" } );
	}
);
probe(
	'oidc create: bad-scheme + control-byte redirect URIs',
	sub {
		$t->ua->post(
			'/oidc',
			form => {
				clientName   => 'c',
				clientType   => 'confidential',
				signingAlg   => 'RS256',
				redirectURIs => "javascript:alert(1)\r\nnot a uri\r\n$ctrl\r\nfile:///etc/passwd"
			}
		);
	}
);
probe(
	'oidc create: oversized redirect + junk scopes',
	sub {
		$t->ua->post(
			'/oidc',
			form => {
				clientName   => 'c',
				clientType   => 'public',
				signingAlg   => 'none',
				redirectURIs => "https://x.example.com/$huge",
				scopes       => "openid $ctrl $huge"
			}
		);
	}
);

done_testing;
