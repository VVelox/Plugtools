#!perl
use strict;
use warnings;

# Tests App::Nisaba's netgroup (nisNetgroup) CRUD against a real (in-memory)
# LDAP server via Net::LDAP::Server::Test. See t/lib/NisabaLDAPTest.pm for
# the harness details.

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

my $netgroupbase = $pt->{ini}{''}{netgroupbase};
ok( $pt->netgroupbaseConfigured, 'netgroupbaseConfigured is true' );

# ── Empty base ──────────────────────────────────────────────────────────────

my ( $netgroups, $err ) = pt_try( sub { $pt->getNetgroups } );
is( $err, '', 'getNetgroups on empty base succeeds' );
is_deeply( $netgroups, [], 'getNetgroups is empty initially' );

# ── addNetgroup ─────────────────────────────────────────────────────────────

( my $ret, $err ) = pt_try(
	sub {
		$pt->addNetgroup(
			{
				group       => 'webservers',
				triples     => [ '(www1,,example.com)', '(www2,,example.com)' ],
				description => 'Web server hosts',
			}
		);
	}
);
is( $err, '', 'addNetgroup with triples and description succeeds' );

my ($entry);
( $entry, $err ) = pt_try( sub { $pt->getNetgroupEntry( { group => 'webservers' } ) } );
is( $err, '', 'getNetgroupEntry succeeds' );
isa_ok( $entry, 'Net::LDAP::Entry', 'netgroup entry' );
like( $entry->dn, qr/^cn=webservers,\Q$netgroupbase\E$/, 'netgroup DN is under netgroupbase' );
is( $entry->get_value('cn'),          'webservers',       'cn round-trips' );
is( $entry->get_value('description'), 'Web server hosts', 'description round-trips' );
my @triples = sort $entry->get_value('nisNetgroupTriple');
is_deeply( \@triples, [ '(www1,,example.com)', '(www2,,example.com)' ], 'multi-valued triples round-trip' );

# A second netgroup with members referencing the first.
( $ret, $err ) = pt_try(
	sub {
		$pt->addNetgroup(
			{
				group   => 'allhosts',
				members => ['webservers'],
			}
		);
	}
);
is( $err, '', 'addNetgroup with a member netgroup succeeds' );
( $entry, $err ) = pt_try( sub { $pt->getNetgroupEntry( { group => 'allhosts' } ) } );
is_deeply( [ $entry->get_value('memberNisNetgroup') ], ['webservers'], 'memberNisNetgroup round-trips' );

( $netgroups, $err ) = pt_try( sub { $pt->getNetgroups } );
is( $err, '', 'getNetgroups succeeds with entries present' );
is_deeply(
	[ sort map { $_->get_value('cn') } @{ $netgroups // [] } ],
	[ 'allhosts', 'webservers' ],
	'getNetgroups returns both netgroups'
);

# Error paths.
( $ret, $err ) = pt_try( sub { $pt->addNetgroup( {} ) } );
isnt( $err, '', 'addNetgroup without a name fails' );
is( $pt->error, 67, 'missing netgroup name sets error 67' );

( $entry, $err ) = pt_try( sub { $pt->getNetgroupEntry( { group => 'nosuch' } ) } );
isnt( $err, '', 'lookup of unknown netgroup fails' );
is( $pt->error, 15, 'unknown netgroup sets error 15' );

# ── netgroupDescriptionChange ───────────────────────────────────────────────

( $ret, $err ) = pt_try(
	sub {
		$pt->netgroupDescriptionChange( { group => 'webservers', description => 'All the web hosts' } );
	}
);
is( $err, '', 'netgroupDescriptionChange set succeeds' );
( $entry, $err ) = pt_try( sub { $pt->getNetgroupEntry( { group => 'webservers' } ) } );
is( $entry->get_value('description'), 'All the web hosts', 'description change visible' );

( $ret, $err ) = pt_try( sub { $pt->netgroupDescriptionChange( { group => 'webservers', description => '' } ) } );
is( $err, '', 'netgroupDescriptionChange clear succeeds' );
( $entry, $err ) = pt_try( sub { $pt->getNetgroupEntry( { group => 'webservers' } ) } );
is( $entry->get_value('description'), undef, 'description cleared' );

( $ret, $err ) = pt_try( sub { $pt->netgroupDescriptionChange( { group => 'nosuch', description => 'X' } ) } );
isnt( $err, '', 'description change on unknown netgroup fails' );
is( $pt->error, 15, 'unknown netgroup sets error 15' );

# ── netgroupTripleAdd / netgroupTripleRemove ────────────────────────────────

( $ret, $err ) = pt_try( sub { $pt->netgroupTripleAdd( { group => 'webservers', triple => '(www3,,example.com)' } ) } );
is( $err, '', 'netgroupTripleAdd succeeds' );
( $entry, $err ) = pt_try( sub { $pt->getNetgroupEntry( { group => 'webservers' } ) } );
@triples = sort $entry->get_value('nisNetgroupTriple');
is( scalar @triples, 3, 'triple added (3 present)' );

( $ret, $err )
	= pt_try( sub { $pt->netgroupTripleRemove( { group => 'webservers', triple => '(www3,,example.com)' } ) } );
is( $err, '', 'netgroupTripleRemove succeeds' );
( $entry, $err ) = pt_try( sub { $pt->getNetgroupEntry( { group => 'webservers' } ) } );
@triples = sort $entry->get_value('nisNetgroupTriple');
is_deeply( \@triples, [ '(www1,,example.com)', '(www2,,example.com)' ], 'removed triple is gone, others remain' );

( $ret, $err ) = pt_try( sub { $pt->netgroupTripleAdd( { group => 'webservers' } ) } );
isnt( $err, '', 'netgroupTripleAdd without a triple fails' );
is( $pt->error, 68, 'missing triple sets error 68' );

( $ret, $err ) = pt_try( sub { $pt->netgroupTripleAdd( { group => 'nosuch', triple => '(x,,y)' } ) } );
isnt( $err, '', 'triple add on unknown netgroup fails' );
is( $pt->error, 15, 'unknown netgroup sets error 15' );

# ── netgroupMemberAdd / netgroupMemberRemove ────────────────────────────────

( $ret, $err ) = pt_try( sub { $pt->netgroupMemberAdd( { group => 'allhosts', member => 'dbservers' } ) } );
is( $err, '', 'netgroupMemberAdd succeeds' );
( $entry, $err ) = pt_try( sub { $pt->getNetgroupEntry( { group => 'allhosts' } ) } );
is_deeply( [ sort $entry->get_value('memberNisNetgroup') ], [ 'dbservers', 'webservers' ], 'member added' );

( $ret, $err ) = pt_try( sub { $pt->netgroupMemberRemove( { group => 'allhosts', member => 'dbservers' } ) } );
is( $err, '', 'netgroupMemberRemove succeeds' );
( $entry, $err ) = pt_try( sub { $pt->getNetgroupEntry( { group => 'allhosts' } ) } );
is_deeply( [ $entry->get_value('memberNisNetgroup') ], ['webservers'], 'removed member is gone, original remains' );

( $ret, $err ) = pt_try( sub { $pt->netgroupMemberAdd( { group => 'allhosts' } ) } );
isnt( $err, '', 'netgroupMemberAdd without a member fails' );
is( $pt->error, 69, 'missing member sets error 69' );

# ── deleteNetgroup ──────────────────────────────────────────────────────────

( $ret, $err ) = pt_try( sub { $pt->deleteNetgroup( { group => 'allhosts' } ) } );
is( $err, '', 'deleteNetgroup succeeds' );

( $entry, $err ) = pt_try( sub { $pt->getNetgroupEntry( { group => 'allhosts' } ) } );
isnt( $err, '', 'deleted netgroup is gone' );

( $netgroups, $err ) = pt_try( sub { $pt->getNetgroups } );
is_deeply( [ map { $_->get_value('cn') } @{ $netgroups // [] } ],
	['webservers'], 'remaining netgroup intact after delete' );

( $ret, $err ) = pt_try( sub { $pt->deleteNetgroup( { group => 'allhosts' } ) } );
isnt( $err, '', 'deleting a nonexistent netgroup fails' );
is( $pt->error, 15, 'unknown netgroup delete sets error 15' );

( $ret, $err ) = pt_try( sub { $pt->deleteNetgroup( {} ) } );
isnt( $err, '', 'deleteNetgroup without a name fails' );
is( $pt->error, 67, 'missing netgroup name sets error 67' );

# ── netgroupbase not configured ─────────────────────────────────────────────

{
	local $pt->{ini}{''}{netgroupbase} = '';
	( $ret, $err ) = pt_try( sub { $pt->addNetgroup( { group => 'x' } ) } );
	isnt( $err, '', 'addNetgroup fails when netgroupbase is unset' );
	is( $pt->error, 66, 'unset netgroupbase sets error 66 (netgroupbaseNotConfigured)' );
}

done_testing;
