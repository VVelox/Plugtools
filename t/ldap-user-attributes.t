#!perl
use strict;
use warnings;

# Tests App::Nisaba's inetOrgPerson attribute management (title, mail,
# telephone, ...), CN handling, and group hygiene helpers (groupClean,
# removeUserFromGroups) against the in-memory LDAP server. See
# t/lib/NisabaLDAPTest.pm for the harness details.
#
# Schema-dependent families (TOTP, passkey, oidcSubject, SSH keys) live in
# the real-slapd tests instead — they need subschema discovery.

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

# ── Fixtures ────────────────────────────────────────────────────────────────

my ( $ret, $err, $entry );

( $ret, $err ) = pt_try( sub { $pt->addGroup( { group => 'staff', gid => 5000 } ) } );
is( $err, '', 'fixture group added' );
( $ret, $err ) = pt_try( sub { $pt->addUser( { user => 'alice', uid => 6000, group => 'staff' } ) } );
is( $err, '', 'fixture user added' );

sub fetch_alice {
	my ($e) = pt_try( sub { $pt->getUserEntry( { user => 'alice' } ) } );
	return $e;
}

# ── userConvertToInetOrgPerson ──────────────────────────────────────────────

( $ret, $err ) = pt_try( sub { $pt->userConvertToInetOrgPerson( { user => 'alice' } ) } );
is( $err, '', 'userConvertToInetOrgPerson succeeds' );

$entry = fetch_alice();
my %oc = map { lc($_) => 1 } $entry->get_value('objectClass');
ok( $oc{inetorgperson}, 'inetOrgPerson objectClass added' );
ok( !$oc{account},      'account objectClass dropped' );
is( $entry->get_value('sn'), 'alice', 'sn fallback set from the username' );

# Conversion is idempotent: converting again succeeds without error.
( $ret, $err ) = pt_try( sub { $pt->userConvertToInetOrgPerson( { user => 'alice' } ) } );
is( $err, '', 'converting an already-converted user is not an error' );
is( $ret, 1,  'double conversion is idempotent (returns 1)' );

# ── Single-valued "change" methods ──────────────────────────────────────────
# Each replaces the previous value; spot-check the per-method missing-arg
# error codes on a couple of them.

my @changes = (
	# [ method, arg-key, value, LDAP attribute ]
	[ 'userTitleChange',             'title',             'Senior Engineer',  'title' ],
	[ 'userRoomNumberChange',        'roomNumber',        '42B',              'roomNumber' ],
	[ 'userEmployeeNumberChange',    'employeeNumber',    'E1234',            'employeeNumber' ],
	[ 'userEmployeeTypeChange',      'employeeType',      'contractor',       'employeeType' ],
	[ 'userGivenNameChange',         'givenName',         'Alice',            'givenName' ],
	[ 'userSNchange',                'sn',                'Wonderland',       'sn' ],
	[ 'userDisplayNameChange',       'displayName',       'Alice Wonderland', 'displayName' ],
	[ 'userHomePostalAddressChange', 'homePostalAddress', '123 Main St',      'homePostalAddress' ],
);

for my $c (@changes) {
	my ( $method, $key, $value, $attr ) = @$c;
	( $ret, $err ) = pt_try( sub { $pt->$method( { user => 'alice', $key => $value } ) } );
	is( $err, '', "$method succeeds" );
	$entry = fetch_alice();
	is( $entry->get_value($attr), $value, "$attr round-trips" );
}

# Replacement, not accumulation.
( $ret, $err ) = pt_try( sub { $pt->userTitleChange( { user => 'alice', title => 'Principal Engineer' } ) } );
is( $err, '', 'second title change succeeds' );
$entry = fetch_alice();
is_deeply( [ $entry->get_value('title') ], ['Principal Engineer'], 'title replaced, not accumulated' );

# Missing-value error codes (representative subset).
( $ret, $err ) = pt_try( sub { $pt->userTitleChange( { user => 'alice' } ) } );
is( $pt->error, 52, 'missing title sets error 52 (noTitle)' );
( $ret, $err ) = pt_try( sub { $pt->userSNchange( { user => 'alice' } ) } );
is( $pt->error, 58, 'missing sn sets error 58 (noSN)' );
( $ret, $err ) = pt_try( sub { $pt->userTitleChange( { user => 'nosuch', title => 'X' } ) } );
is( $pt->error, 17, 'change on unknown user sets error 17' );

# ── Multi-valued add/remove methods ─────────────────────────────────────────

my @multi = (
	# [ add-method, remove-method, arg-key, value1, value2, LDAP attribute ]
	[ 'userMailAdd', 'userMailRemove', 'mail', 'alice@example.com', 'a2@example.com', 'mail' ],
	[
		'userTelephoneNumberAdd', 'userTelephoneNumberRemove',
		'telephoneNumber',        '+1-555-0100',
		'+1-555-0101',            'telephoneNumber'
	],
	[ 'userMobileAdd', 'userMobileRemove', 'mobile', '+1-555-0200', '+1-555-0201', 'mobile' ],
	[
		'userPreferredLanguageAdd', 'userPreferredLanguageRemove',
		'preferredLanguage',        'en',
		'de',                       'preferredLanguage'
	],
	[
		'userLabeledURIAdd', 'userLabeledURIRemove', 'labeledURI', 'https://a.example',
		'https://b.example', 'labeledURI'
	],
	[
		'userPostalAddressAdd', 'userPostalAddressRemove', 'postalAddress', '1 First St',
		'2 Second St',          'postalAddress'
	],
);

for my $m (@multi) {
	my ( $add, $remove, $key, $v1, $v2, $attr ) = @$m;

	( $ret, $err ) = pt_try( sub { $pt->$add( { user => 'alice', $key => $v1 } ) } );
	is( $err, '', "$add first value succeeds" );
	( $ret, $err ) = pt_try( sub { $pt->$add( { user => 'alice', $key => $v2 } ) } );
	is( $err, '', "$add second value succeeds" );

	$entry = fetch_alice();
	is_deeply( [ sort $entry->get_value($attr) ], [ sort ( $v1, $v2 ) ], "$attr holds both values" );

	( $ret, $err ) = pt_try( sub { $pt->$remove( { user => 'alice', $key => $v2 } ) } );
	is( $err, '', "$remove succeeds" );
	$entry = fetch_alice();
	is_deeply( [ $entry->get_value($attr) ], [$v1], "$attr keeps the remaining value" );
} ## end for my $m (@multi)

( $ret, $err ) = pt_try( sub { $pt->userMailAdd( { user => 'alice' } ) } );
is( $pt->error, 49, 'missing mail sets error 49 (noMail)' );

# description is special: Net::LDAP::posixAccount pre-populates it with the
# gecos value at creation, so account for the existing value.
$entry = fetch_alice();
my @desc_initial = $entry->get_value('description');
is( scalar @desc_initial, 1, 'posixAccount creation pre-populated one description' );

( $ret, $err ) = pt_try( sub { $pt->userDescriptionAdd( { user => 'alice', description => 'extra desc' } ) } );
is( $err, '', 'userDescriptionAdd succeeds' );
$entry = fetch_alice();
is_deeply(
	[ sort $entry->get_value('description') ],
	[ sort ( @desc_initial, 'extra desc' ) ],
	'description added alongside the pre-populated value'
);

( $ret, $err ) = pt_try( sub { $pt->userDescriptionRemove( { user => 'alice', description => 'extra desc' } ) } );
is( $err, '', 'userDescriptionRemove succeeds' );
$entry = fetch_alice();
is_deeply( [ $entry->get_value('description') ], \@desc_initial, 'description back to the original set' );

# ── userCNadd / userCNremove ────────────────────────────────────────────────

$entry = fetch_alice();
my @cn_before = $entry->get_value('cn');

( $ret, $err ) = pt_try( sub { $pt->userCNadd( { user => 'alice', cn => 'Alice W' } ) } );
is( $err, '', 'userCNadd succeeds' );
$entry = fetch_alice();
is( scalar( () = $entry->get_value('cn') ), scalar(@cn_before) + 1, 'cn value added' );

( $ret, $err ) = pt_try( sub { $pt->userCNremove( { user => 'alice', cn => 'Alice W' } ) } );
is( $err, '', 'userCNremove succeeds' );
$entry = fetch_alice();
is_deeply( [ sort $entry->get_value('cn') ], [ sort @cn_before ], 'cn back to the original set' );

# Removing the last CN must be refused (error 71).
my @cn_now = $entry->get_value('cn');
if ( @cn_now == 1 ) {
	( $ret, $err ) = pt_try( sub { $pt->userCNremove( { user => 'alice', cn => $cn_now[0] } ) } );
	isnt( $err, '', 'removing the last cn fails' );
	is( $pt->error, 71, 'last cn sets error 71 (lastCN)' );
} else {
	fail( 'expected exactly one cn for the lastCN check, got ' . scalar @cn_now );
	fail('lastCN error-code check skipped');
}

( $ret, $err ) = pt_try( sub { $pt->userCNadd( { user => 'alice' } ) } );
is( $pt->error, 70, 'missing cn sets error 70 (noCN)' );

# ── ensureInetOrgPerson auto-upgrade path ───────────────────────────────────
# Attribute changes on a user that was never explicitly converted must add
# the inetOrgPerson chain on the fly.

( $ret, $err ) = pt_try( sub { $pt->addUser( { user => 'bob', uid => 6001, group => 'staff' } ) } );
is( $err, '', 'second fixture user added' );

( $ret, $err ) = pt_try( sub { $pt->userTitleChange( { user => 'bob', title => 'Intern' } ) } );
is( $err, '', 'attribute change on unconverted user succeeds' );

( $entry, $err ) = pt_try( sub { $pt->getUserEntry( { user => 'bob' } ) } );
%oc = map { lc($_) => 1 } $entry->get_value('objectClass');
ok( $oc{inetorgperson}, 'ensureInetOrgPerson added inetOrgPerson on the fly' );
is( $entry->get_value('title'), 'Intern', 'title set on the upgraded entry' );
is( $entry->get_value('sn'),    'bob',    'sn fallback added during auto-upgrade' );

# ── removeUserFromGroups / groupClean ───────────────────────────────────────

( $ret, $err ) = pt_try( sub { $pt->addGroup( { group => 'proj', gid => 5100 } ) } );
is( $err, '', 'membership group added' );
( $ret, $err ) = pt_try( sub { $pt->groupAddUser( { group => 'proj', user => 'alice' } ) } );
( $ret, $err ) = pt_try( sub { $pt->groupAddUser( { group => 'proj', user => 'bob' } ) } );
is( $err, '', 'members added to proj' );

( $ret, $err ) = pt_try( sub { $pt->removeUserFromGroups('bob') } );
is( $err, '', 'removeUserFromGroups succeeds' );
my ($groups);
( $groups, $err ) = pt_try( sub { $pt->getGroups } );
my ($proj) = grep { $_->get_value('cn') eq 'proj' } @{ $groups // [] };
is_deeply( [ $proj->get_value('memberUid') ], ['alice'], 'bob removed from proj, alice remains' );

# groupClean: prune memberUid values that reference users that no longer
# exist. 'ghost' never existed as a user.
( $ret, $err ) = pt_try( sub { $pt->groupAddUser( { group => 'proj', user => 'ghost' } ) } );
is( $err, '', 'dangling member added for the groupClean test' );

( $ret, $err ) = pt_try( sub { $pt->groupClean } );
is( $err, '', 'groupClean succeeds' );
( $groups, $err ) = pt_try( sub { $pt->getGroups } );
($proj) = grep { $_->get_value('cn') eq 'proj' } @{ $groups // [] };
is_deeply( [ $proj->get_value('memberUid') ], ['alice'], 'groupClean pruned the dangling member' );

done_testing;
