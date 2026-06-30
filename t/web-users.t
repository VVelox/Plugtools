#!perl
use strict;
use warnings;

# Stub File::ShareDir::dist_dir so the web app can start without the dist
# being installed. Must happen before App::Nisaba::Web is loaded.
use File::Basename ();
use File::Spec;
BEGIN {
	my $share = File::Spec->rel2abs(
		File::Spec->catdir( File::Basename::dirname(__FILE__), File::Spec->updir, 'share' )
	);
	require File::ShareDir;
	no warnings 'redefine';
	*File::ShareDir::dist_dir = sub { $share };
}

use Test::More;
use Test::Mojo;

eval { require App::Nisaba::Web };
if ($@) {
	plan skip_all => "App::Nisaba::Web failed to load: $@";
}

# ── Fake Net::LDAP::Entry ─────────────────────────────────────────────────────

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

# ── Fake user and group entries ──────────────────────────────────────────────

my $usr_alice = FakeEntry->new(
	_dn           => 'uid=alice,ou=users,dc=example,dc=com',
	uid           => 'alice',
	uidNumber     => '1000',
	gidNumber     => '1000',
	homeDirectory => '/home/alice',
	loginShell    => '/bin/bash',
	gecos         => 'Alice A',
	objectClass   => [ 'posixAccount', 'inetOrgPerson', 'person', 'organizationalPerson' ],
	cn            => ['Alice A'],
	sn            => 'A',
	mail          => ['alice@example.com'],
);

my $usr_bob = FakeEntry->new(
	_dn           => 'uid=bob,ou=users,dc=example,dc=com',
	uid           => 'bob',
	uidNumber     => '1001',
	gidNumber     => '1001',
	homeDirectory => '/home/bob',
	loginShell    => '/bin/zsh',
	gecos         => 'Bob B',
	objectClass   => ['posixAccount'],
	cn            => ['Bob B'],
);

my $grp_admins = FakeEntry->new(
	_dn       => 'cn=admins,ou=groups,dc=example,dc=com',
	cn        => 'admins',
	gidNumber => '1000',
	memberUid => ['alice'],
);

my $grp_users = FakeEntry->new(
	_dn       => 'cn=users,ou=groups,dc=example,dc=com',
	cn        => 'users',
	gidNumber => '1001',
	memberUid => [ 'alice', 'bob' ],
);

# ── Stub helper installer ─────────────────────────────────────────────────────

sub _install_stubs {
	my ( $app, %overrides ) = @_;

	my %defaults = (
		error                      => sub { 0 },
		errorString                => sub { '' },
		getUsers                   => sub { [ $usr_alice, $usr_bob ] },
		getGroups                  => sub { [ $grp_admins, $grp_users ] },
		getUserEntry               => sub { $usr_alice },
		addUser                    => sub { },
		deleteUser                 => sub { },
		userHasPassword            => sub { 1 },
		userSetPass                => sub { },
		userRemovePassword         => sub { },
		userGECOSchange            => sub { },
		userShellChange            => sub { },
		userUIDchange              => sub { },
		userGIDchange              => sub { },
		userHomeChange             => sub { },
		userTitleChange            => sub { },
		userRoomNumberChange       => sub { },
		userEmployeeNumberChange   => sub { },
		userEmployeeTypeChange     => sub { },
		userMailAdd                => sub { },
		userMailRemove             => sub { },
		userTelephoneNumberAdd     => sub { },
		userTelephoneNumberRemove  => sub { },
		userMobileAdd              => sub { },
		userMobileRemove           => sub { },
		userPreferredLanguageAdd   => sub { },
		userPreferredLanguageRemove => sub { },
		userLabeledURIAdd          => sub { },
		userLabeledURIRemove       => sub { },
		userSNchange               => sub { },
		userGivenNameChange        => sub { },
		userDisplayNameChange      => sub { },
		userHomePostalAddressChange => sub { },
		userDescriptionAdd         => sub { },
		userDescriptionRemove      => sub { },
		userPostalAddressAdd       => sub { },
		userPostalAddressRemove    => sub { },
		userCNadd                  => sub { },
		userCNremove               => sub { },
		userSSHPublicKeyAdd        => sub { },
		userSSHPublicKeyRemove     => sub { },
		userConvertToInetOrgPerson => sub { },
		userConvertToLdapPublicKey => sub { },
		userConvertToTotp          => sub { },
		userConvertToPasskeyUser   => sub { },
		userTotpGenerateSecret     => sub { 'JBSWY3DPEHPK3PXP' },
		userTotpVerify             => sub { 1 },
		userTotpStatusSet          => sub { },
		userTotpEnrolledDateSet    => sub { },
		userTotpSecretSet          => sub { },
		userTotpSecretRemove       => sub { },
		userTotpAlgorithmSet       => sub { },
		userTotpPeriodSet          => sub { },
		userTotpDigitsSet          => sub { },
		userTotpScratchCodeAdd     => sub { },
		userTotpInfoGet            => sub { { totpStatus => 'active', totpScratchCodes => [] } },
		userPasskeyInfoGet         => sub { { credentials => [] } },
		userPasskeyCredentialRemove => sub { },
		ldapPublicKeyAvailable     => sub { 1 },
		totpSchemaAvailable        => sub { 1 },
		passkeySchemaAvailable     => sub { 1 },
		groupAddUser               => sub { },
		groupRemoveUser            => sub { },
		netgroupbaseConfigured     => sub { 0 },
		oidcbaseConfigured         => sub { 0 },
	);

	my %methods = ( %defaults, %overrides );

	my $fake_pt = bless {
		ini => { '' => { totpAdminAddScratchCodes => 0 } },
	}, 'FakePT';
	for my $name ( keys %methods ) {
		no strict 'refs';
		no warnings 'redefine';
		*{"FakePT::$name"} = $methods{$name};
	}

	$app->helper( pt => sub { $fake_pt } );
}

# Add a same-host Referer to every POST so the middleware check passes
sub _add_referer_hook {
	my $t = shift;
	$t->ua->on(
		start => sub {
			my ( $ua, $tx ) = @_;
			return unless $tx->req->method eq 'POST';
			my $host = $tx->req->url->to_abs->host_port // 'localhost';
			$tx->req->headers->referrer("http://$host/");
		}
	);
}

my $t = Test::Mojo->new('App::Nisaba::Web');
_install_stubs( $t->app );
_add_referer_hook($t);

# Inject an admin session so routes behind require_login are accessible
$t->app->hook( before_dispatch => sub { $_[0]->session( admin_user => 'testadmin' ) } );

# ── index ─────────────────────────────────────────────────────────────────────

$t->get_ok('/users')
  ->status_is(200)
  ->content_like( qr/alice/, 'index lists alice' )
  ->content_like( qr/bob/,   'index lists bob' );

# index when getUsers dies → flash is stored; appears on the next request
_install_stubs( $t->app, getUsers => sub { die "LDAP down\n" } );
$t->get_ok('/users')->status_is(200);    # triggers flash, renders empty list
_install_stubs( $t->app );               # restore working stubs
$t->get_ok('/users')
  ->status_is(200)
  ->content_like( qr/LDAP down/, 'index shows flash error on subsequent request' );

# ── add (GET) ─────────────────────────────────────────────────────────────────

$t->get_ok('/users/add')
  ->status_is(200)
  ->content_like( qr/Add User/, 'add form renders' );

# ── create ────────────────────────────────────────────────────────────────────

my $created;
_install_stubs(
	$t->app,
	addUser => sub {
		my ( $self, $args ) = @_;
		$created = $args;
	},
);

$t->post_ok( '/users', form => { user => 'charlie', uid => '2000', gecos => 'Charlie C' } )
  ->status_is(302)
  ->header_like( Location => qr{/users$}, 'create redirects to index' );
is( $created->{user},  'charlie',   'addUser received correct username' );
is( $created->{uid},   '2000',      'addUser received correct UID' );
is( $created->{gecos}, 'Charlie C', 'addUser received correct GECOS' );

# create with minimal params (auto-assign)
$created = undef;
_install_stubs(
	$t->app,
	addUser => sub {
		my ( $self, $args ) = @_;
		$created = $args;
	},
);
$t->post_ok( '/users', form => { user => 'dave' } )
  ->status_is(302)
  ->header_like( Location => qr{/users$}, 'create with minimal params redirects to index' );
is( $created->{user}, 'dave', 'addUser received username' );
ok( !exists $created->{uid}, 'UID not passed when empty' );

# create failure → redirect back to add
_install_stubs( $t->app, addUser => sub { die "create failed\n" } );
$t->post_ok( '/users', form => { user => 'bad' } )
  ->status_is(302)
  ->header_like( Location => qr{/users/add}, 'create failure redirects to add form' );
_install_stubs( $t->app );

# ── show ──────────────────────────────────────────────────────────────────────

$t->get_ok('/users/alice')
  ->status_is(200)
  ->content_like( qr/alice/,   'show renders username' )
  ->content_like( qr/1000/,    'show renders UID' )
  ->content_like( qr/Alice A/, 'show renders GECOS' )
  ->content_like( qr/admins/,  'show renders member group' );

# show when getUserEntry fails → redirect to index
_install_stubs( $t->app, getUserEntry => sub { die "lookup failed\n" } );
$t->get_ok('/users/missing')
  ->status_is(302)
  ->header_like( Location => qr{/users$}, 'show redirects to index for failed lookup' );
_install_stubs( $t->app );

# ── update: GECOS ─────────────────────────────────────────────────────────────

my $gecos_args;
_install_stubs(
	$t->app,
	userGECOSchange => sub { my ( $self, $args ) = @_; $gecos_args = $args },
);
$t->post_ok( '/users/alice', form => { action => 'gecos', gecos => 'New GECOS' } )
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'GECOS update redirects to show' );
is( $gecos_args->{gecos}, 'New GECOS', 'userGECOSchange got correct value' );

# ── update: shell ─────────────────────────────────────────────────────────────

my $shell_args;
_install_stubs(
	$t->app,
	userShellChange => sub { my ( $self, $args ) = @_; $shell_args = $args },
);
$t->post_ok( '/users/alice', form => { action => 'shell', shell => '/bin/zsh' } )
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'shell update redirects to show' );
is( $shell_args->{shell}, '/bin/zsh', 'userShellChange got correct shell' );

# ── update: UID ───────────────────────────────────────────────────────────────

my $uid_args;
_install_stubs(
	$t->app,
	userUIDchange => sub { my ( $self, $args ) = @_; $uid_args = $args },
);
$t->post_ok( '/users/alice', form => { action => 'uid', uid => '5000' } )
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'UID update redirects to show' );
is( $uid_args->{uid}, '5000', 'userUIDchange got correct UID' );

# ── update: GID ───────────────────────────────────────────────────────────────

my $gid_args;
_install_stubs(
	$t->app,
	userGIDchange => sub { my ( $self, $args ) = @_; $gid_args = $args },
);
$t->post_ok( '/users/alice', form => { action => 'gid', gid => '6000' } )
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'GID update redirects to show' );
is( $gid_args->{gid}, '6000', 'userGIDchange got correct GID' );

# ── update: home ──────────────────────────────────────────────────────────────

my $home_args;
_install_stubs(
	$t->app,
	userHomeChange => sub { my ( $self, $args ) = @_; $home_args = $args },
);
$t->post_ok( '/users/alice', form => { action => 'home', home => '/home/newalice' } )
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'home update redirects to show' );
is( $home_args->{home}, '/home/newalice', 'userHomeChange got correct home' );

# ── update: inetOrgPerson single-value fields ─────────────────────────────────

for my $test (
	[ 'title',       'userTitleChange',       'title',       'Engineer' ],
	[ 'roomNumber',  'userRoomNumberChange',  'roomNumber',  '42' ],
	[ 'employeeNumber', 'userEmployeeNumberChange', 'employeeNumber', 'EMP001' ],
	[ 'employeeType',   'userEmployeeTypeChange',   'employeeType',   'Full Time' ],
	[ 'sn',          'userSNchange',          'sn',          'Smith' ],
	[ 'givenName',   'userGivenNameChange',   'givenName',   'Alice' ],
	[ 'displayName', 'userDisplayNameChange', 'displayName', 'Alice Smith' ],
	[ 'homePostalAddress', 'userHomePostalAddressChange', 'homePostalAddress', '123 Main St' ],
) {
	my ( $action, $method, $field, $value ) = @{$test};
	my $captured;
	_install_stubs(
		$t->app,
		$method => sub { my ( $self, $args ) = @_; $captured = $args },
	);
	$t->post_ok( '/users/alice', form => { action => $action, $field => $value } )
	  ->status_is(302)
	  ->header_like( Location => qr{/users/alice}, "$action update redirects to show" );
	is( $captured->{$field}, $value, "$method got correct $field" );
}

# ── update: multi-value add/remove ────────────────────────────────────────────

for my $test (
	[ 'mail_add',               'userMailAdd',              'mail',              'test@example.com' ],
	[ 'mail_remove',            'userMailRemove',           'mail',              'test@example.com' ],
	[ 'telephoneNumber_add',    'userTelephoneNumberAdd',   'telephoneNumber',   '+1234567890' ],
	[ 'telephoneNumber_remove', 'userTelephoneNumberRemove', 'telephoneNumber',  '+1234567890' ],
	[ 'mobile_add',             'userMobileAdd',            'mobile',            '+0987654321' ],
	[ 'mobile_remove',          'userMobileRemove',         'mobile',            '+0987654321' ],
	[ 'preferredLanguage_add',  'userPreferredLanguageAdd', 'preferredLanguage', 'en' ],
	[ 'preferredLanguage_remove', 'userPreferredLanguageRemove', 'preferredLanguage', 'en' ],
	[ 'labeledURI_add',         'userLabeledURIAdd',        'labeledURI',        'https://example.com' ],
	[ 'labeledURI_remove',      'userLabeledURIRemove',     'labeledURI',        'https://example.com' ],
	[ 'description_add',        'userDescriptionAdd',       'description',       'A user' ],
	[ 'description_remove',     'userDescriptionRemove',    'description',       'A user' ],
	[ 'postalAddress_add',      'userPostalAddressAdd',     'postalAddress',     '456 Elm St' ],
	[ 'postalAddress_remove',   'userPostalAddressRemove',  'postalAddress',     '456 Elm St' ],
	[ 'cn_add',                 'userCNadd',                'cn',                'Alice New' ],
	[ 'cn_remove',              'userCNremove',             'cn',                'Alice Old' ],
) {
	my ( $action, $method, $field, $value ) = @{$test};
	my $captured;
	_install_stubs(
		$t->app,
		$method => sub { my ( $self, $args ) = @_; $captured = $args },
	);
	$t->post_ok( '/users/alice', form => { action => $action, $field => $value } )
	  ->status_is(302)
	  ->header_like( Location => qr{/users/alice}, "$action redirects to show" );
	is( $captured->{$field}, $value, "$method got correct $field" );
}

# ── update: SSH key add/remove ────────────────────────────────────────────────

my $sshkey_args;
_install_stubs(
	$t->app,
	userSSHPublicKeyAdd => sub { my ( $self, $args ) = @_; $sshkey_args = $args },
);
$t->post_ok( '/users/alice', form => { action => 'sshkey_add', key => 'ssh-rsa AAAA...' } )
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'sshkey_add redirects to show' );
is( $sshkey_args->{key}, 'ssh-rsa AAAA...', 'userSSHPublicKeyAdd got correct key' );

my $sshkey_rm_args;
_install_stubs(
	$t->app,
	userSSHPublicKeyRemove => sub { my ( $self, $args ) = @_; $sshkey_rm_args = $args },
);
$t->post_ok( '/users/alice', form => { action => 'sshkey_remove', key => 'ssh-rsa AAAA...' } )
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'sshkey_remove redirects to show' );
is( $sshkey_rm_args->{key}, 'ssh-rsa AAAA...', 'userSSHPublicKeyRemove got correct key' );

# ── update: TOTP actions ──────────────────────────────────────────────────────

for my $test (
	[ 'totp_status',        'userTotpStatusSet',       'status',    'active' ],
	[ 'totp_algorithm',     'userTotpAlgorithmSet',    'algorithm', 'SHA256' ],
	[ 'totp_period',        'userTotpPeriodSet',       'period',    '30' ],
	[ 'totp_digits',        'userTotpDigitsSet',       'digits',    '6' ],
	[ 'totp_secret',        'userTotpSecretSet',       'secret',    'JBSWY3DP' ],
) {
	my ( $action, $method, $field, $value ) = @{$test};
	my $captured;
	_install_stubs(
		$t->app,
		$method => sub { my ( $self, $args ) = @_; $captured = $args },
	);
	$t->post_ok( '/users/alice', form => { action => $action, $field => $value } )
	  ->status_is(302)
	  ->header_like( Location => qr{/users/alice}, "$action redirects to show" );
	is( $captured->{$field}, $value, "$method got correct $field" );
}

# TOTP secret remove
my $totp_rm_called;
_install_stubs(
	$t->app,
	userTotpSecretRemove => sub { $totp_rm_called = 1 },
);
$t->post_ok( '/users/alice', form => { action => 'totp_secret_remove' } )
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'totp_secret_remove redirects to show' );
ok( $totp_rm_called, 'userTotpSecretRemove was called' );

# TOTP enrolled now
my $totp_enrolled_called;
_install_stubs(
	$t->app,
	userTotpEnrolledDateSet => sub { $totp_enrolled_called = 1 },
);
$t->post_ok( '/users/alice', form => { action => 'totp_enrolled_now' } )
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'totp_enrolled_now redirects to show' );
ok( $totp_enrolled_called, 'userTotpEnrolledDateSet was called' );

# TOTP scratch add — disabled by default
_install_stubs( $t->app );
$t->post_ok( '/users/alice', form => { action => 'totp_scratch_add', code => '123456' } )
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'totp_scratch_add disabled redirects to show' );
# Flash should contain "disabled" message — verify on next request
$t->get_ok('/users/alice')
  ->status_is(200)
  ->content_like( qr/disabled/, 'totp_scratch_add shows disabled message' );

# ── update: unknown action ───────────────────────────────────────────────────

_install_stubs( $t->app );
$t->post_ok( '/users/alice', form => { action => 'bogus' } )
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'unknown action redirects to show' );

# ── update: failure ──────────────────────────────────────────────────────────

_install_stubs( $t->app, userGECOSchange => sub { die "update failed\n" } );
$t->post_ok( '/users/alice', form => { action => 'gecos', gecos => 'fail' } )
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'update failure redirects to show' );
_install_stubs( $t->app );

# ── delete ────────────────────────────────────────────────────────────────────

my $delete_args;
_install_stubs(
	$t->app,
	deleteUser => sub { my ( $self, $args ) = @_; $delete_args = $args },
);
$t->post_ok( '/users/alice/delete', form => { removeHome => '1', removeGroup => '0' } )
  ->status_is(302)
  ->header_like( Location => qr{/users$}, 'delete redirects to index' );
is( $delete_args->{user},        'alice', 'deleteUser got correct user' );
is( $delete_args->{removeHome},  '1',     'deleteUser got removeHome flag' );
is( $delete_args->{removeGroup}, '0',     'deleteUser got removeGroup flag' );

# delete with defaults
$delete_args = undef;
_install_stubs(
	$t->app,
	deleteUser => sub { my ( $self, $args ) = @_; $delete_args = $args },
);
$t->post_ok('/users/alice/delete')
  ->status_is(302)
  ->header_like( Location => qr{/users$}, 'delete with defaults redirects to index' );
is( $delete_args->{removeHome},  '0', 'deleteUser defaults removeHome to 0' );
is( $delete_args->{removeGroup}, '1', 'deleteUser defaults removeGroup to 1' );

# delete failure
_install_stubs( $t->app, deleteUser => sub { die "delete failed\n" } );
$t->post_ok('/users/alice/delete')
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'delete failure redirects to show' );
_install_stubs( $t->app );

# ── password ──────────────────────────────────────────────────────────────────

my $pass_args;
_install_stubs(
	$t->app,
	userSetPass => sub { my ( $self, $args ) = @_; $pass_args = $args },
);
$t->post_ok( '/users/alice/password', form => { pass => 's3cret' } )
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'password set redirects to show' );
is( $pass_args->{pass}, 's3cret', 'userSetPass got correct password' );

# password failure
_install_stubs( $t->app, userSetPass => sub { die "set pass failed\n" } );
$t->post_ok( '/users/alice/password', form => { pass => 'x' } )
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'password failure redirects to show' );
_install_stubs( $t->app );

# ── remove_password ───────────────────────────────────────────────────────────

my $rmpass_called;
_install_stubs(
	$t->app,
	userRemovePassword => sub { $rmpass_called = 1 },
);
$t->post_ok('/users/alice/password/remove')
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'remove_password redirects to show' );
ok( $rmpass_called, 'userRemovePassword was called' );

# remove_password failure
_install_stubs( $t->app, userRemovePassword => sub { die "rm pass failed\n" } );
$t->post_ok('/users/alice/password/remove')
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'remove_password failure redirects to show' );
_install_stubs( $t->app );

# ── inetorgperson ─────────────────────────────────────────────────────────────

my $iop_called;
_install_stubs(
	$t->app,
	userConvertToInetOrgPerson => sub { $iop_called = 1 },
);
$t->post_ok('/users/alice/inetorgperson')
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'inetorgperson redirects to show' );
ok( $iop_called, 'userConvertToInetOrgPerson was called' );

# inetorgperson failure
_install_stubs( $t->app, userConvertToInetOrgPerson => sub { die "convert failed\n" } );
$t->post_ok('/users/alice/inetorgperson')
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'inetorgperson failure redirects to show' );
_install_stubs( $t->app );

# ── lpk (SSH public key support) ─────────────────────────────────────────────

my $lpk_called;
_install_stubs(
	$t->app,
	userConvertToLdapPublicKey => sub { $lpk_called = 1 },
);
$t->post_ok('/users/alice/lpk')
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'lpk redirects to show' );
ok( $lpk_called, 'userConvertToLdapPublicKey was called' );

# lpk failure
_install_stubs( $t->app, userConvertToLdapPublicKey => sub { die "lpk failed\n" } );
$t->post_ok('/users/alice/lpk')
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'lpk failure redirects to show' );
_install_stubs( $t->app );

# ── totp enable ───────────────────────────────────────────────────────────────

my $totp_called;
_install_stubs(
	$t->app,
	userConvertToTotp => sub { $totp_called = 1 },
);
$t->post_ok('/users/alice/totp')
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'totp enable redirects to show' );
ok( $totp_called, 'userConvertToTotp was called' );

# totp failure
_install_stubs( $t->app, userConvertToTotp => sub { die "totp failed\n" } );
$t->post_ok('/users/alice/totp')
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'totp enable failure redirects to show' );
_install_stubs( $t->app );

# ── totp generate ─────────────────────────────────────────────────────────────

my $totp_gen_called;
_install_stubs(
	$t->app,
	userTotpGenerateSecret => sub { $totp_gen_called = 1; return 'NEWSECRET' },
);
$t->post_ok('/users/alice/totp/generate')
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'totp generate redirects to show' );
ok( $totp_gen_called, 'userTotpGenerateSecret was called' );

# totp generate failure
_install_stubs( $t->app, userTotpGenerateSecret => sub { die "gen failed\n" } );
$t->post_ok('/users/alice/totp/generate')
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'totp generate failure redirects to show' );
_install_stubs( $t->app );

# ── totp verify ───────────────────────────────────────────────────────────────

my ( $totp_verify_called, $totp_status_set, $totp_enrolled_set );
_install_stubs(
	$t->app,
	userTotpVerify         => sub { $totp_verify_called = 1; return 1 },
	userTotpStatusSet      => sub { $totp_status_set = 1 },
	userTotpEnrolledDateSet => sub { $totp_enrolled_set = 1 },
);
$t->post_ok( '/users/alice/totp/verify', form => { code => '123456' } )
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'totp verify redirects to show' );
ok( $totp_verify_called, 'userTotpVerify was called' );
ok( $totp_status_set,    'userTotpStatusSet was called on success' );
ok( $totp_enrolled_set,  'userTotpEnrolledDateSet was called on success' );

# totp verify failure
_install_stubs( $t->app, userTotpVerify => sub { return 0 } );
$t->post_ok( '/users/alice/totp/verify', form => { code => '000000' } )
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'totp verify failure redirects to show' );
_install_stubs( $t->app );

# ── passkey enable ────────────────────────────────────────────────────────────

my $passkey_called;
_install_stubs(
	$t->app,
	userConvertToPasskeyUser => sub { $passkey_called = 1 },
);
$t->post_ok('/users/alice/passkeys/enable')
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'passkey enable redirects to show' );
ok( $passkey_called, 'userConvertToPasskeyUser was called' );

# passkey enable failure
_install_stubs( $t->app, userConvertToPasskeyUser => sub { die "passkey failed\n" } );
$t->post_ok('/users/alice/passkeys/enable')
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'passkey enable failure redirects to show' );
_install_stubs( $t->app );

# ── passkey remove ────────────────────────────────────────────────────────────

my $passkey_rm_args;
_install_stubs(
	$t->app,
	userPasskeyCredentialRemove => sub { my ( $self, $args ) = @_; $passkey_rm_args = $args },
);
$t->post_ok('/users/alice/passkeys/cred123/remove')
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'passkey remove redirects to show' );
is( $passkey_rm_args->{credentialId}, 'cred123', 'userPasskeyCredentialRemove got correct credentialId' );

# passkey remove failure
_install_stubs( $t->app, userPasskeyCredentialRemove => sub { die "pk rm failed\n" } );
$t->post_ok('/users/alice/passkeys/cred123/remove')
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'passkey remove failure redirects to show' );
_install_stubs( $t->app );

# ── add_to_group ──────────────────────────────────────────────────────────────

my @group_add_calls;
_install_stubs(
	$t->app,
	groupAddUser => sub { my ( $self, $args ) = @_; push @group_add_calls, $args },
);
$t->post_ok( '/users/alice/groups', form => { group => [ 'users', 'admins' ] } )
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'add_to_group redirects to show' );
is( scalar @group_add_calls, 2, 'groupAddUser called for each group' );
is( $group_add_calls[0]->{group}, 'users',  'first group correct' );
is( $group_add_calls[1]->{group}, 'admins', 'second group correct' );

# add_to_group partial failure
@group_add_calls = ();
my $call_count = 0;
_install_stubs(
	$t->app,
	groupAddUser => sub {
		my ( $self, $args ) = @_;
		$call_count++;
		die "failed\n" if $call_count == 2;
	},
);
$t->post_ok( '/users/alice/groups', form => { group => [ 'g1', 'g2' ] } )
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'partial failure redirects to show' );
_install_stubs( $t->app );

# ── remove_from_group ─────────────────────────────────────────────────────────

my $rmgrp_args;
_install_stubs(
	$t->app,
	groupRemoveUser => sub { my ( $self, $args ) = @_; $rmgrp_args = $args },
);
$t->post_ok('/users/alice/groups/admins/remove')
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'remove_from_group redirects to show' );
is( $rmgrp_args->{user},  'alice',  'groupRemoveUser got correct user' );
is( $rmgrp_args->{group}, 'admins', 'groupRemoveUser got correct group' );

# remove_from_group failure
_install_stubs( $t->app, groupRemoveUser => sub { die "rm group failed\n" } );
$t->post_ok('/users/alice/groups/admins/remove')
  ->status_is(302)
  ->header_like( Location => qr{/users/alice}, 'remove_from_group failure redirects to show' );
_install_stubs( $t->app );

done_testing;
