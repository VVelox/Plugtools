#!perl
use strict;
use warnings;

# Tests App::Nisaba's plugin dispatch system against the in-memory LDAP
# server. Plugins are Perl modules named in the config (comma-separated per
# hook), loaded in-process and called as Class->plugin(\%opts, \%args); a
# plugin returning error aborts the surrounding operation. NisabaTestPlugin
# (t/lib) records every invocation so the hooks can be asserted.

use Test::More;
use File::Basename ();
use File::Spec;
use lib File::Spec->catdir( File::Basename::dirname(__FILE__), 'lib' );
use NisabaLDAPTest;
use NisabaTestPlugin;

my ( $env, $skip ) = NisabaLDAPTest::setup(
	ini => {
		pluginAddGroup       => 'NisabaTestPlugin',
		pluginAddUser        => 'NisabaTestPlugin',
		pluginDeleteGroup    => 'NisabaTestPlugin',
		pluginDeleteUser     => 'NisabaTestPlugin',
		pluginGroupAddUser   => 'NisabaTestPlugin',
		pluginGroupRemoveUser => 'NisabaTestPlugin',
		# a hook wired to two plugins, and one wired to a module that
		# cannot be loaded — both used by the direct-call tests below
		pluginMulti => 'NisabaTestPlugin,NisabaTestPlugin',
		pluginBogus => 'No::Such::Module::NisabaXyz',
	},
);
plan skip_all => $skip if $skip;

my $pt = $env->{pt};
sub pt_try { return NisabaLDAPTest::pt_try( $pt, @_ ) }

END { NisabaLDAPTest::teardown($env) }

alarm(120);
local $SIG{ALRM} = sub { die "test watchdog expired — LDAP server wedged?\n" };

sub calls_for {
	my ($do) = @_;
	return grep { $_->{do} eq $do } @NisabaTestPlugin::CALLS;
}

my ( $ret, $err );

# ── Hooks fire during CRUD operations ───────────────────────────────────────

( $ret, $err ) = pt_try( sub { $pt->addGroup( { group => 'devs', gid => 5000 } ) } );
is( $err, '', 'addGroup succeeds with a plugin configured' );

my @c = calls_for('pluginAddGroup');
is( scalar @c, 1, 'pluginAddGroup fired once' );
is( $c[0]{args}{group}, 'devs', 'plugin received the group name in %args' );
like( $c[0]{entry_dn} // '', qr/^cn=devs,/, 'plugin received the Net::LDAP::Entry being created' );
ok( $c[0]{has_self}, 'plugin received the App::Nisaba object' );
ok( $c[0]{has_ldap}, 'plugin received the LDAP connection' );

( $ret, $err ) = pt_try( sub { $pt->addUser( { user => 'alice', uid => 6000, group => 'devs' } ) } );
is( $err, '', 'addUser succeeds with a plugin configured' );
@c = calls_for('pluginAddUser');
is( scalar @c, 1, 'pluginAddUser fired once' );
is( $c[0]{args}{user}, 'alice', 'plugin received the user name in %args' );

# addUser with an auto-created primary group fires BOTH hooks.
( $ret, $err ) = pt_try( sub { $pt->addUser( { user => 'bob' } ) } );
is( $err, '', 'addUser with auto-group succeeds' );
@c = calls_for('pluginAddGroup');
is( scalar @c, 2, 'auto-created primary group fired pluginAddGroup too' );
is( $c[1]{args}{group}, 'bob', 'auto-group plugin call carries the group name' );

( $ret, $err ) = pt_try( sub { $pt->groupAddUser( { group => 'devs', user => 'alice' } ) } );
is( $err, '', 'groupAddUser succeeds' );
@c = calls_for('pluginGroupAddUser');
is( scalar @c, 1, 'pluginGroupAddUser fired' );
is( $c[0]{args}{user},  'alice', 'membership plugin call carries the user' );
is( $c[0]{args}{group}, 'devs',  'membership plugin call carries the group' );

( $ret, $err ) = pt_try( sub { $pt->groupRemoveUser( { group => 'devs', user => 'alice' } ) } );
is( $err, '', 'groupRemoveUser succeeds' );
is( scalar calls_for('pluginGroupRemoveUser'), 1, 'pluginGroupRemoveUser fired' );

( $ret, $err ) = pt_try( sub { $pt->deleteUser( { user => 'bob' } ) } );
is( $err, '', 'deleteUser succeeds' );
@c = calls_for('pluginDeleteUser');
is( scalar @c, 1, 'pluginDeleteUser fired' );
# bob's empty auto-created primary group is cascade-deleted → delete hook too.
@c = calls_for('pluginDeleteGroup');
is( scalar @c, 1, 'cascade group removal fired pluginDeleteGroup' );
is( $c[0]{args}{group} // ( $c[0]{entry_dn} =~ /^cn=([^,]+)/ )[0], 'bob',
	'delete hook saw the cascaded group' );

# ── A failing plugin aborts the operation ───────────────────────────────────

{
	local $NisabaTestPlugin::FAIL = 1;
	( $ret, $err ) = pt_try( sub { $pt->addGroup( { group => 'failgrp', gid => 5100 } ) } );
	isnt( $err, '', 'operation fails when the plugin reports an error' );
	is( $pt->error, 45, 'plugin failure sets error 45 (pluginError)' );
}
( $ret, $err ) = pt_try( sub { $pt->isLDAPgroup('failgrp') } );
ok( !$ret, 'group was NOT created after the plugin aborted the add' );

# The same operation succeeds once the plugin behaves again.
( $ret, $err ) = pt_try( sub { $pt->addGroup( { group => 'failgrp', gid => 5100 } ) } );
is( $err, '', 'operation succeeds after the plugin stops failing' );

# ── Direct plugin() calls: validation and dispatch errors ───────────────────

my $ldap  = $pt->connect;
my $entry = Net::LDAP::Entry->new;
$entry->dn('cn=direct,dc=example,dc=com');

my $n_before = scalar @NisabaTestPlugin::CALLS;
( $ret, $err ) = pt_try(
	sub { $pt->plugin( { ldap => $ldap, entry => $entry, do => 'pluginMulti' }, { tag => 'x' } ) } );
is( $err, '', 'direct plugin() call succeeds' );
is( scalar @NisabaTestPlugin::CALLS, $n_before + 2,
	'comma-separated hook ran the plugin list (both entries)' );

( $ret, $err ) = pt_try( sub { $pt->plugin( { entry => $entry, do => 'pluginMulti' }, {} ) } );
is( $pt->error, 38, 'missing ldap sets error 38 (noLDAP)' );

( $ret, $err ) = pt_try( sub { $pt->plugin( { ldap => $ldap, entry => $entry }, {} ) } );
is( $pt->error, 39, 'missing do sets error 39 (noPluginDo)' );

( $ret, $err ) = pt_try( sub { $pt->plugin( { ldap => $ldap, do => 'pluginMulti' }, {} ) } );
is( $pt->error, 42, 'missing entry sets error 42 (noLDAPentry)' );

( $ret, $err ) = pt_try(
	sub { $pt->plugin( { ldap => $ldap, entry => 'not-an-entry', do => 'pluginMulti' }, {} ) } );
is( $pt->error, 43, 'non-entry sets error 43 (entryNotLDAPEntry)' );

( $ret, $err ) = pt_try(
	sub { $pt->plugin( { ldap => 'not-ldap', entry => $entry, do => 'pluginMulti' }, {} ) } );
is( $pt->error, 44, 'non-LDAP object sets error 44 (ldapNotLDAP)' );

( $ret, $err ) = pt_try(
	sub { $pt->plugin( { ldap => $ldap, entry => $entry, do => 'pluginNotConfigured' }, {} ) } );
is( $pt->error, 40, 'unconfigured hook sets error 40 (pluginConfigMissing)' );

( $ret, $err ) = pt_try(
	sub { $pt->plugin( { ldap => $ldap, entry => $entry, do => 'pluginBogus' }, {} ) } );
is( $pt->error, 41, 'unloadable plugin module sets error 41 (pluginExecFailed)' );

# ── The shipped Dump plugin loads and runs ──────────────────────────────────

SKIP: {
	eval { require App::Nisaba::Plugins::Dump; 1 }
		or skip 'App::Nisaba::Plugins::Dump not loadable', 2;

	local $pt->{ini}{''}{pluginDump} = 'App::Nisaba::Plugins::Dump';

	# Dump prints %opts/%args to STDOUT; keep the TAP stream clean.
	my $out = '';
	do {
		local *STDOUT;
		open STDOUT, '>', \$out;
		( $ret, $err ) = pt_try(
			sub { $pt->plugin( { ldap => $ldap, entry => $entry, do => 'pluginDump' }, { k => 'v' } ) } );
	};
	is( $err, '', 'shipped Dump plugin runs without error' );
	like( $out, qr/\%opts=/, 'Dump plugin printed the dump' );
}

done_testing;
