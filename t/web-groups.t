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

# ── Fake group and user entries ──────────────────────────────────────────────

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

my $usr_alice = FakeEntry->new(
	_dn           => 'uid=alice,ou=users,dc=example,dc=com',
	uid           => 'alice',
	uidNumber     => '1000',
	gidNumber     => '1000',
	homeDirectory => '/home/alice',
	loginShell    => '/bin/bash',
	gecos         => 'Alice',
);

my $usr_bob = FakeEntry->new(
	_dn           => 'uid=bob,ou=users,dc=example,dc=com',
	uid           => 'bob',
	uidNumber     => '1001',
	gidNumber     => '1001',
	homeDirectory => '/home/bob',
	loginShell    => '/bin/zsh',
	gecos         => 'Bob',
);

# ── Stub helper installer ─────────────────────────────────────────────────────

sub _install_stubs {
	my ( $app, %overrides ) = @_;

	my %defaults = (
		error                    => sub { 0 },
		errorString              => sub { '' },
		getGroups                => sub { [ $grp_admins, $grp_users ] },
		getUsers                 => sub { [ $usr_alice, $usr_bob ] },
		addGroup                 => sub { },
		deleteGroup              => sub { },
		groupClean               => sub { },
		groupGIDchange           => sub { },
		groupDescriptionChange   => sub { },
		groupAddUser             => sub { },
		groupRemoveUser          => sub { },
		netgroupbaseConfigured   => sub { 0 },
		oidcbaseConfigured       => sub { 0 },
	);

	my %methods = ( %defaults, %overrides );

	my $fake_pt = bless { ini => { '' => {} } }, 'FakePT';
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

$t->get_ok('/groups')
  ->status_is(200)
  ->content_like( qr/admins/, 'index lists admins group' )
  ->content_like( qr/users/,  'index lists users group' );

# index when getGroups dies → flash is stored; appears on the next request
_install_stubs( $t->app, getGroups => sub { die "LDAP down\n" } );
$t->get_ok('/groups')->status_is(200);    # triggers flash, renders empty list
_install_stubs( $t->app );                # restore working stubs
$t->get_ok('/groups')
  ->status_is(200)
  ->content_like( qr/LDAP down/, 'index shows flash error on subsequent request' );

# ── add (GET) ─────────────────────────────────────────────────────────────────

$t->get_ok('/groups/add')
  ->status_is(200)
  ->content_like( qr/Add Group/, 'add form renders' );

# ── create ────────────────────────────────────────────────────────────────────

my $created;
_install_stubs(
	$t->app,
	addGroup => sub {
		my ( $self, $args ) = @_;
		$created = $args;
	},
);

$t->post_ok( '/groups', form => { group => 'devs', gid => '2000' } )
  ->status_is(302)
  ->header_like( Location => qr{/groups$}, 'create redirects to index' );
is( $created->{group}, 'devs', 'addGroup received correct group name' );
is( $created->{gid},   '2000', 'addGroup received correct GID' );

# create without GID (auto-assign)
$created = undef;
_install_stubs(
	$t->app,
	addGroup => sub {
		my ( $self, $args ) = @_;
		$created = $args;
	},
);
$t->post_ok( '/groups', form => { group => 'nogidevs' } )
  ->status_is(302)
  ->header_like( Location => qr{/groups$}, 'create without GID redirects to index' );
is( $created->{group}, 'nogidevs', 'addGroup received group name with no GID' );
ok( !exists $created->{gid}, 'GID not passed when empty' );

# create failure → redirect back to add
_install_stubs( $t->app, addGroup => sub { die "create failed\n" } );
$t->post_ok( '/groups', form => { group => 'bad' } )
  ->status_is(302)
  ->header_like( Location => qr{/groups/add}, 'create failure redirects to add form' );
_install_stubs( $t->app );

# ── clean ─────────────────────────────────────────────────────────────────────

_install_stubs( $t->app );
$t->post_ok('/groups/clean')
  ->status_is(302)
  ->header_like( Location => qr{/groups$}, 'clean redirects to index' );

# clean failure
_install_stubs( $t->app, groupClean => sub { die "clean failed\n" } );
$t->post_ok('/groups/clean')
  ->status_is(302)
  ->header_like( Location => qr{/groups$}, 'clean failure redirects to index' );
_install_stubs( $t->app );

# ── show ──────────────────────────────────────────────────────────────────────

$t->get_ok('/groups/admins')
  ->status_is(200)
  ->content_like( qr/admins/,  'show renders group name' )
  ->content_like( qr/1000/,    'show renders GID' )
  ->content_like( qr/alice/,   'show renders member' );

# show: non-members listed for add-member dropdown
$t->get_ok('/groups/admins')
  ->status_is(200)
  ->content_like( qr/bob/, 'show renders non-member in dropdown' );

# show when group not found → redirect to index
$t->get_ok('/groups/nonexistent')
  ->status_is(302)
  ->header_like( Location => qr{/groups$}, 'show redirects to index for unknown group' );

# show when getGroups fails → redirect to index
_install_stubs( $t->app, getGroups => sub { die "LDAP error\n" } );
$t->get_ok('/groups/admins')
  ->status_is(302)
  ->header_like( Location => qr{/groups$}, 'show redirects to index when getGroups fails' );
_install_stubs( $t->app );

# ── update: GID change ───────────────────────────────────────────────────────

my $gid_args;
_install_stubs(
	$t->app,
	groupGIDchange => sub { my ( $self, $args ) = @_; $gid_args = $args },
);
$t->post_ok( '/groups/admins', form => { action => 'gid', gid => '5000' } )
  ->status_is(302)
  ->header_like( Location => qr{/groups/admins}, 'GID change redirects to show' );
is( $gid_args->{group}, 'admins', 'groupGIDchange got correct group' );
is( $gid_args->{gid},   '5000',  'groupGIDchange got correct GID' );

# GID change failure
_install_stubs( $t->app, groupGIDchange => sub { die "gid change failed\n" } );
$t->post_ok( '/groups/admins', form => { action => 'gid', gid => '9999' } )
  ->status_is(302)
  ->header_like( Location => qr{/groups/admins}, 'GID change failure redirects to show' );
_install_stubs( $t->app );

# ── update: description change ───────────────────────────────────────────────

my $desc_args;
_install_stubs(
	$t->app,
	groupDescriptionChange => sub { my ( $self, $args ) = @_; $desc_args = $args },
);
$t->post_ok( '/groups/admins', form => { action => 'description', description => 'Admin group' } )
  ->status_is(302)
  ->header_like( Location => qr{/groups/admins}, 'description update redirects to show' );
is( $desc_args->{group},       'admins',      'groupDescriptionChange got correct group' );
is( $desc_args->{description}, 'Admin group', 'groupDescriptionChange got correct description' );

# ── update: unknown action ───────────────────────────────────────────────────

_install_stubs( $t->app );
$t->post_ok( '/groups/admins', form => { action => 'bogus' } )
  ->status_is(302)
  ->header_like( Location => qr{/groups/admins}, 'unknown action redirects to show' );

# ── update: default action is gid ────────────────────────────────────────────

my $default_gid_args;
_install_stubs(
	$t->app,
	groupGIDchange => sub { my ( $self, $args ) = @_; $default_gid_args = $args },
);
$t->post_ok( '/groups/admins', form => { gid => '7777' } )
  ->status_is(302)
  ->header_like( Location => qr{/groups/admins}, 'default action (no action param) redirects to show' );
is( $default_gid_args->{gid}, '7777', 'default action calls groupGIDchange' );

# ── delete ────────────────────────────────────────────────────────────────────

my $deleted;
_install_stubs(
	$t->app,
	deleteGroup => sub { my ( $self, $group ) = @_; $deleted = $group },
);
$t->post_ok('/groups/admins/delete')
  ->status_is(302)
  ->header_like( Location => qr{/groups$}, 'delete redirects to index' );
is( $deleted, 'admins', 'deleteGroup called with correct group name' );

# delete failure
_install_stubs( $t->app, deleteGroup => sub { die "delete failed\n" } );
$t->post_ok('/groups/admins/delete')
  ->status_is(302)
  ->header_like( Location => qr{/groups/admins}, 'delete failure redirects to show' );
_install_stubs( $t->app );

# ── add_member ────────────────────────────────────────────────────────────────

my $add_member_args;
_install_stubs(
	$t->app,
	groupAddUser => sub { my ( $self, $args ) = @_; $add_member_args = $args },
);
$t->post_ok( '/groups/admins/members', form => { user => 'bob' } )
  ->status_is(302)
  ->header_like( Location => qr{/groups/admins}, 'add_member redirects to show' );
is( $add_member_args->{group}, 'admins', 'groupAddUser got correct group' );
is( $add_member_args->{user},  'bob',    'groupAddUser got correct user' );

# add_member failure
_install_stubs( $t->app, groupAddUser => sub { die "add member failed\n" } );
$t->post_ok( '/groups/admins/members', form => { user => 'bob' } )
  ->status_is(302)
  ->header_like( Location => qr{/groups/admins}, 'add_member failure redirects to show' );
_install_stubs( $t->app );

# ── remove_member ─────────────────────────────────────────────────────────────

my $rm_member_args;
_install_stubs(
	$t->app,
	groupRemoveUser => sub { my ( $self, $args ) = @_; $rm_member_args = $args },
);
$t->post_ok('/groups/admins/members/alice/delete')
  ->status_is(302)
  ->header_like( Location => qr{/groups/admins}, 'remove_member redirects to show' );
is( $rm_member_args->{group}, 'admins', 'groupRemoveUser got correct group' );
is( $rm_member_args->{user},  'alice',  'groupRemoveUser got correct user' );

# remove_member failure
_install_stubs( $t->app, groupRemoveUser => sub { die "remove member failed\n" } );
$t->post_ok('/groups/admins/members/alice/delete')
  ->status_is(302)
  ->header_like( Location => qr{/groups/admins}, 'remove_member failure redirects to show' );
_install_stubs( $t->app );

done_testing;
