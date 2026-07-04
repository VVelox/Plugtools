#!perl
use strict;
use warnings;

# Tests App::Nisaba's user and group CRUD against a real (in-memory) LDAP
# server via Net::LDAP::Server::Test. See t/lib/NisabaLDAPTest.pm for the
# harness details.
#
# The harness config sets createHome=0 / removeHome=0 / NSScheck=0, so no
# filesystem or NSS state is ever touched: everything is LDAP-only.

use Test::More;
use File::Basename ();
use File::Spec;
use lib File::Spec->catdir( File::Basename::dirname(__FILE__), 'lib' );
use NisabaLDAPTest;

my ( $env, $skip ) = NisabaLDAPTest::setup();
plan skip_all => $skip if $skip;

my $pt = $env->{pt};
sub pt_try { return NisabaLDAPTest::pt_try( $pt, @_ ) }

END { NisabaLDAPTest::teardown($env) }

alarm(120);
local $SIG{ALRM} = sub { die "test watchdog expired — LDAP server wedged?\n" };

my $userbase  = $pt->{ini}{''}{userbase};
my $groupbase = $pt->{ini}{''}{groupbase};

# ── Empty bases ─────────────────────────────────────────────────────────────

my ( $groups, $err ) = pt_try( sub { $pt->getGroups } );
is( $err, '', 'getGroups on empty base succeeds' );
is_deeply( $groups, [], 'getGroups is empty initially' );

my ($users);
( $users, $err ) = pt_try( sub { $pt->getUsers } );
is( $err, '', 'getUsers on empty base succeeds' );
is_deeply( $users, [], 'getUsers is empty initially' );

# ── addGroup ────────────────────────────────────────────────────────────────

( my $ret, $err ) = pt_try( sub { $pt->addGroup( { group => 'devs', gid => 5000 } ) } );
is( $err, '', 'addGroup with explicit GID succeeds' );

my ($dn);
( $dn, $err ) = pt_try( sub { $pt->findGroupDN('devs') } );
is( $err, '', 'findGroupDN succeeds' );
is( $dn, "cn=devs,$groupbase", 'group DN is cn-based under groupbase' );

( $ret, $err ) = pt_try( sub { $pt->isLDAPgroup('devs') } );
ok( $ret, 'isLDAPgroup true for existing group' );

# Auto-assigned GID: first free at/above GIDstart (default 1001).
( $ret, $err ) = pt_try( sub { $pt->addGroup( { group => 'autogid' } ) } );
is( $err, '', 'addGroup with auto GID succeeds' );
( $groups, $err ) = pt_try( sub { $pt->getGroups } );
my ($autogid_entry) = grep { $_->get_value('cn') eq 'autogid' } @{ $groups // [] };
is( ( $autogid_entry ? $autogid_entry->get_value('gidNumber') : undef ),
	1001, 'auto-assigned GID starts at GIDstart' );

# Error paths.
( $ret, $err ) = pt_try( sub { $pt->addGroup( { group => 'devs' } ) } );
isnt( $err, '', 'duplicate group name fails' );
is( $pt->error, 10, 'duplicate group sets error 10 (groupExists)' );

( $ret, $err ) = pt_try( sub { $pt->addGroup( { group => 'devs2', gid => 5000 } ) } );
isnt( $err, '', 'duplicate GID fails' );
is( $pt->error, 20, 'duplicate GID sets error 20 (GIDexists)' );

( $ret, $err ) = pt_try( sub { $pt->addGroup( { group => 'devs3', gid => 'abc' } ) } );
isnt( $err, '', 'non-numeric GID fails' );
is( $pt->error, 8, 'non-numeric GID sets error 8' );

( $ret, $err ) = pt_try( sub { $pt->addGroup( {} ) } );
isnt( $err, '', 'addGroup without a name fails' );
is( $pt->error, 6, 'missing group name sets error 6' );

# ── addUser ─────────────────────────────────────────────────────────────────

# Explicit everything; primary group 'devs' already exists, so its GID is used.
( $ret, $err ) = pt_try(
	sub {
		$pt->addUser(
			{
				user  => 'alice',
				uid   => 6000,
				group => 'devs',
				gecos => 'Alice Wonderland',
				shell => '/bin/sh',
			}
		);
	}
);
is( $err, '', 'addUser with explicit values succeeds' );

my ($entry);
( $entry, $err ) = pt_try( sub { $pt->getUserEntry( { user => 'alice' } ) } );
is( $err, '', 'getUserEntry succeeds' );
isa_ok( $entry, 'Net::LDAP::Entry', 'user entry' );
is( $entry->get_value('uid'),           'alice',             'uid round-trips' );
is( $entry->get_value('uidNumber'),     6000,                'uidNumber round-trips' );
is( $entry->get_value('gidNumber'),     5000,                'gidNumber comes from the primary group' );
is( $entry->get_value('gecos'),         'Alice Wonderland',  'gecos round-trips' );
is( $entry->get_value('loginShell'),    '/bin/sh',           'loginShell round-trips' );
is( $entry->get_value('homeDirectory'), '/home/alice/',      'homeDirectory built from HOMEproto' );

( $dn, $err ) = pt_try( sub { $pt->findUserDN('alice') } );
is( $err, '', 'findUserDN succeeds' );
like( $dn, qr/^uid=alice,\Q$userbase\E$/, 'user DN is uid-based under userbase' );

( $ret, $err ) = pt_try( sub { $pt->isLDAPuser('alice') } );
ok( $ret, 'isLDAPuser true for existing user' );

# Defaults: auto UID, primary group auto-created with the user's name.
( $ret, $err ) = pt_try( sub { $pt->addUser( { user => 'bob' } ) } );
is( $err, '', 'addUser with defaults succeeds' );

( $entry, $err ) = pt_try( sub { $pt->getUserEntry( { user => 'bob' } ) } );
is( $entry->get_value('uidNumber'), 1001, 'auto-assigned UID starts at UIDstart' );
is( $entry->get_value('gecos'), 'bob', 'gecos defaults to the username' );
is( $entry->get_value('loginShell'), $pt->{ini}{''}{defaultShell}, 'shell defaults from config' );

( $ret, $err ) = pt_try( sub { $pt->isLDAPgroup('bob') } );
ok( $ret, 'primary group was auto-created with the user name' );
my ($bob_group);
( $bob_group, $err ) = pt_try( sub { $pt->getGroups } );
my ($bg) = grep { $_->get_value('cn') eq 'bob' } @{ $bob_group // [] };
( $entry, $err ) = pt_try( sub { $pt->getUserEntry( { user => 'bob' } ) } );
is( $entry->get_value('gidNumber'), $bg->get_value('gidNumber'),
	"user's gidNumber matches the auto-created group" );

# Error paths.
( $ret, $err ) = pt_try( sub { $pt->addUser( { user => 'alice' } ) } );
isnt( $err, '', 'duplicate user fails' );
is( $pt->error, 9, 'duplicate user sets error 9 (userExists)' );

( $ret, $err ) = pt_try( sub { $pt->addUser( { user => 'carol', uid => '12b4' } ) } );
isnt( $err, '', 'non-numeric UID fails' );
is( $pt->error, 7, 'non-numeric UID sets error 7' );

( $ret, $err ) = pt_try( sub { $pt->addUser( {} ) } );
isnt( $err, '', 'addUser without a name fails' );
is( $pt->error, 5, 'missing user name sets error 5' );

( $entry, $err ) = pt_try( sub { $pt->getUserEntry( { user => 'nosuchuser' } ) } );
isnt( $err, '', 'getUserEntry for unknown user fails' );
is( $pt->error, 17, 'unknown user sets error 17 (userNotFound)' );

( $ret, $err ) = pt_try( sub { $pt->isLDAPuser('nosuchuser') } );
ok( !$ret, 'isLDAPuser false for unknown user' );

# ── User attribute changes ──────────────────────────────────────────────────

( $ret, $err ) = pt_try( sub { $pt->userGECOSchange( { user => 'alice', gecos => 'Alice W.' } ) } );
is( $err, '', 'userGECOSchange succeeds' );
( $ret, $err ) = pt_try( sub { $pt->userShellChange( { user => 'alice', shell => '/bin/zsh' } ) } );
is( $err, '', 'userShellChange succeeds' );
( $ret, $err ) = pt_try( sub { $pt->userHomeChange( { user => 'alice', home => '/srv/alice' } ) } );
is( $err, '', 'userHomeChange succeeds' );

( $entry, $err ) = pt_try( sub { $pt->getUserEntry( { user => 'alice' } ) } );
is( $entry->get_value('gecos'),         'Alice W.',   'gecos change visible on re-fetch' );
is( $entry->get_value('loginShell'),    '/bin/zsh',   'shell change visible on re-fetch' );
is( $entry->get_value('homeDirectory'), '/srv/alice', 'home change visible on re-fetch' );

# UID change.
( $ret, $err ) = pt_try( sub { $pt->userUIDchange( { user => 'alice', uid => 6001 } ) } );
is( $err, '', 'userUIDchange succeeds' );
( $entry, $err ) = pt_try( sub { $pt->getUserEntry( { user => 'alice' } ) } );
is( $entry->get_value('uidNumber'), 6001, 'UID change visible on re-fetch' );

( $ret, $err ) = pt_try( sub { $pt->userUIDchange( { user => 'alice', uid => 'x' } ) } );
isnt( $err, '', 'non-numeric UID change fails' );
is( $pt->error, 7, 'non-numeric UID change sets error 7' );

# GID change: target group must exist.
( $ret, $err ) = pt_try( sub { $pt->userGIDchange( { user => 'alice', gid => 99999 } ) } );
isnt( $err, '', 'GID change to a nonexistent group fails' );
is( $pt->error, 14, 'nonexistent target GID sets error 14 (groupNotFound)' );

my $bob_gid = $bg->get_value('gidNumber');
( $ret, $err ) = pt_try( sub { $pt->userGIDchange( { user => 'alice', gid => $bob_gid } ) } );
is( $err, '', 'userGIDchange to an existing group succeeds' );
( $entry, $err ) = pt_try( sub { $pt->getUserEntry( { user => 'alice' } ) } );
is( $entry->get_value('gidNumber'), $bob_gid, 'GID change visible on re-fetch' );
# ... and back to devs for the tests below.
( $ret, $err ) = pt_try( sub { $pt->userGIDchange( { user => 'alice', gid => 5000 } ) } );
is( $err, '', 'userGIDchange back to original group succeeds' );

# ── Group membership ────────────────────────────────────────────────────────

( $ret, $err ) = pt_try( sub { $pt->groupAddUser( { group => 'autogid', user => 'alice' } ) } );
is( $err, '', 'groupAddUser succeeds' );
( $ret, $err ) = pt_try( sub { $pt->groupAddUser( { group => 'autogid', user => 'bob' } ) } );
is( $err, '', 'second member added' );

( $groups, $err ) = pt_try( sub { $pt->getGroups } );
my ($ag) = grep { $_->get_value('cn') eq 'autogid' } @{ $groups // [] };
my @members = sort $ag->get_value('memberUid');
is_deeply( \@members, [ 'alice', 'bob' ], 'memberUid holds both members' );

( $ret, $err ) = pt_try( sub { $pt->groupAddUser( { group => 'nosuchgroup', user => 'alice' } ) } );
isnt( $err, '', 'groupAddUser on unknown group fails' );
is( $pt->error, 14, 'unknown group sets error 14' );

# onlyMember: alice shares 'autogid' with bob → not the only member.
( $ret, $err ) = pt_try( sub { $pt->onlyMember( { user => 'alice', group => 'autogid' } ) } );
ok( !$ret, 'onlyMember false when the group has other members' );

( $ret, $err ) = pt_try( sub { $pt->groupRemoveUser( { group => 'autogid', user => 'bob' } ) } );
is( $err, '', 'groupRemoveUser succeeds' );
( $groups, $err ) = pt_try( sub { $pt->getGroups } );
($ag) = grep { $_->get_value('cn') eq 'autogid' } @{ $groups // [] };
is_deeply( [ $ag->get_value('memberUid') ], ['alice'], 'removed member is gone' );

# ── groupDescriptionChange ──────────────────────────────────────────────────

( $ret, $err ) = pt_try(
	sub { $pt->groupDescriptionChange( { group => 'devs', description => 'Development team' } ) } );
is( $err, '', 'groupDescriptionChange set succeeds' );
( $groups, $err ) = pt_try( sub { $pt->getGroups } );
my ($devs) = grep { $_->get_value('cn') eq 'devs' } @{ $groups // [] };
is( $devs->get_value('description'), 'Development team', 'description set' );

( $ret, $err ) = pt_try( sub { $pt->groupDescriptionChange( { group => 'devs', description => '' } ) } );
is( $err, '', 'groupDescriptionChange clear succeeds' );
( $groups, $err ) = pt_try( sub { $pt->getGroups } );
($devs) = grep { $_->get_value('cn') eq 'devs' } @{ $groups // [] };
is( $devs->get_value('description'), undef, 'description cleared' );

# ── groupGIDchange (with userUpdate following the primary GID) ──────────────

( $ret, $err ) = pt_try( sub { $pt->groupGIDchange( { group => 'devs', gid => 5001 } ) } );
is( $err, '', 'groupGIDchange succeeds' );
( $groups, $err ) = pt_try( sub { $pt->getGroups } );
($devs) = grep { $_->get_value('cn') eq 'devs' } @{ $groups // [] };
is( $devs->get_value('gidNumber'), 5001, 'group GID changed' );

# userUpdate defaults on: alice's primary GID (5000) must have followed.
( $entry, $err ) = pt_try( sub { $pt->getUserEntry( { user => 'alice' } ) } );
is( $entry->get_value('gidNumber'), 5001, "member's primary GID followed the group GID change" );

( $ret, $err ) = pt_try( sub { $pt->groupGIDchange( { group => 'devs', gid => 'bad' } ) } );
isnt( $err, '', 'non-numeric group GID change fails' );
is( $pt->error, 8, 'non-numeric group GID sets error 8' );

# ── userVerifyPassword (bind verification) ──────────────────────────────────
# The harness verifies simple binds against the stored userPassword (see
# _install_bind_verification in t/lib/NisabaLDAPTest.pm). The password is
# written directly through the anchor connection because App::Nisaba's own
# password-set methods use the SetPassword extended operation, which the test
# server does not implement.

my ($alice_dn);
( $alice_dn, $err ) = pt_try( sub { $pt->findUserDN('alice') } );
my $mod = $env->{anchor}->modify( $alice_dn, replace => { userPassword => 'correct horse' } );
is( $mod->code, 0, 'userPassword set directly via the anchor connection' );

( $ret, $err ) = pt_try(
	sub { $pt->userVerifyPassword( { user => 'alice', password => 'correct horse' } ) } );
is( $err, '', 'correct password verifies' );
is( $ret, 1,  'userVerifyPassword returns 1 on success' );

( $ret, $err ) = pt_try(
	sub { $pt->userVerifyPassword( { user => 'alice', password => 'battery staple' } ) } );
isnt( $err, '', 'wrong password is rejected' );
is( $pt->error, 75, 'wrong password sets error 75 (authFailed)' );

# bob exists but has no userPassword: a simple bind as him must fail.
( $ret, $err ) = pt_try(
	sub { $pt->userVerifyPassword( { user => 'bob', password => 'anything' } ) } );
isnt( $err, '', 'user without a stored password is rejected' );
is( $pt->error, 75, 'passwordless user sets error 75 (authFailed)' );

( $ret, $err ) = pt_try(
	sub { $pt->userVerifyPassword( { user => 'nosuchuser', password => 'x' } ) } );
isnt( $err, '', 'unknown user is rejected' );
is( $pt->error, 18, 'unknown user sets error 18 (userNotInLDAP)' );

( $ret, $err ) = pt_try( sub { $pt->userVerifyPassword( { user => 'alice' } ) } );
isnt( $err, '', 'missing password argument fails' );
is( $pt->error, 35, 'missing password sets error 35 (noPassword)' );

( $ret, $err ) = pt_try( sub { $pt->userVerifyPassword( { password => 'x' } ) } );
isnt( $err, '', 'missing user argument fails' );
is( $pt->error, 5, 'missing user sets error 5 (noUser)' );

# The admin/service bind is unaffected by bind verification: connect() still
# works after all of the above.
my $post_ldap = $pt->connect;
ok( $post_ldap && !$pt->error, 'admin connect() still binds with verification active' );

# ── deleteUser ──────────────────────────────────────────────────────────────

# bob: primary group 'bob' was auto-created and bob is its only (implicit)
# member; removeGroup defaults on, so deleting bob should delete group 'bob'
# too, and remove bob's memberUid entries from other groups.
( $ret, $err ) = pt_try( sub { $pt->groupAddUser( { group => 'autogid', user => 'bob' } ) } );
is( $err, '', 're-add bob to autogid before delete' );

( $ret, $err ) = pt_try( sub { $pt->deleteUser( { user => 'bob' } ) } );
is( $err, '', 'deleteUser succeeds' );

( $ret, $err ) = pt_try( sub { $pt->isLDAPuser('bob') } );
ok( !$ret, 'deleted user is gone' );
( $ret, $err ) = pt_try( sub { $pt->isLDAPgroup('bob') } );
ok( !$ret, 'empty primary group removed along with the user' );

( $groups, $err ) = pt_try( sub { $pt->getGroups } );
($ag) = grep { $_->get_value('cn') eq 'autogid' } @{ $groups // [] };
my @after = grep { $_ eq 'bob' } $ag->get_value('memberUid');
is( scalar @after, 0, "deleted user's memberUid removed from other groups" );

( $ret, $err ) = pt_try( sub { $pt->deleteUser( { user => 'bob' } ) } );
isnt( $err, '', 'deleting a nonexistent user fails' );
is( $pt->error, 17, 'unknown user delete sets error 17' );

# ── deleteGroup ─────────────────────────────────────────────────────────────

( $ret, $err ) = pt_try( sub { $pt->deleteGroup('autogid') } );
is( $err, '', 'deleteGroup succeeds' );
( $ret, $err ) = pt_try( sub { $pt->isLDAPgroup('autogid') } );
ok( !$ret, 'deleted group is gone' );

( $ret, $err ) = pt_try( sub { $pt->deleteGroup('autogid') } );
isnt( $err, '', 'deleting a nonexistent group fails' );
is( $pt->error, 10, 'unknown group delete sets error 10' );

( $ret, $err ) = pt_try( sub { $pt->deleteGroup(undef) } );
isnt( $err, '', 'deleteGroup without a name fails' );

# ── Final state ─────────────────────────────────────────────────────────────

( $users, $err ) = pt_try( sub { $pt->getUsers } );
is_deeply( [ sort map { $_->get_value('uid') } @{ $users // [] } ],
	['alice'], 'only alice remains' );
( $groups, $err ) = pt_try( sub { $pt->getGroups } );
is_deeply( [ sort map { $_->get_value('cn') } @{ $groups // [] } ],
	['devs'], 'only devs remains' );

done_testing;
