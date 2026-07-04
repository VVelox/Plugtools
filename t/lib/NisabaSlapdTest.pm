package NisabaSlapdTest;

# Harness for testing App::Nisaba against a REAL OpenLDAP slapd, spawned via
# Test::OpenLDAP on a unix (ldapi://) socket. Complements NisabaLDAPTest
# (Net::LDAP::Server::Test), covering what the in-memory server cannot:
#
#   * the SetPassword extended operation (userSetPass / userSetPassSelf)
#   * subschema discovery via $ldap->schema (the *SchemaAvailable methods)
#   * real schema enforcement and real bind authentication
#
# setup() spawns slapd, then over LDAP (cn=config is writable by the admin
# rootdn) loads:
#
#   * the stock cosine / inetorgperson / nis schemas from the OS's OpenLDAP
#     schema directory (olc-format .ldif files), and
#   * this repo's custom schemas from schemas/*.schema (slapd.conf format,
#     converted to olc attributes by _schema_file_to_olc),
#
# then creates the base tree (suffix + ou=users/groups/oidc/netgroup) and
# points an App::Nisaba instance at the ldapi socket.

use strict;
use warnings;
use File::Basename ();
use File::Spec;
use File::Temp ();

use lib File::Basename::dirname(__FILE__);
use NisabaLDAPTest;    # for pt_try

# Delegate: identical call semantics as the in-memory harness.
*pt_try = \&NisabaLDAPTest::pt_try;

my $SUFFIX = 'dc=example,dc=com';

# Candidate locations of the OS's olc-format schema LDIF files.
my @SCHEMA_DIRS = (
	'/usr/local/etc/openldap/schema',    # FreeBSD
	'/etc/ldap/schema',                  # Debian/Ubuntu
	'/etc/openldap/schema',              # RHEL/Fedora/Arch
);

# Build a test environment. Returns ( $env, undef ) on success or
# ( undef, $skip_reason ). $env: { pt, slapd, admin, uri, config }.
sub setup {
	my (%opts) = @_;

	eval { require Test::OpenLDAP; require Net::LDAP; require Net::LDAP::LDIF; 1 }
		or return ( undef, "Test::OpenLDAP not usable: $@" );
	if ( my $reason = Test::OpenLDAP->skip ) {
		return ( undef, $reason );
	}
	eval { require App::Nisaba; 1 }
		or return ( undef, "App::Nisaba failed to load: $@" );

	my ($schema_dir) = grep { -f File::Spec->catfile( $_, 'nis.ldif' ) } @SCHEMA_DIRS;
	return ( undef, 'could not find the OpenLDAP schema directory (nis.ldif)' )
		unless $schema_dir;

	my $repo_schemas = File::Spec->catdir(
		File::Basename::dirname(__FILE__),
		File::Spec->updir, File::Spec->updir, 'schemas'
	);
	return ( undef, "repo schemas directory not found at $repo_schemas" )
		unless -d $repo_schemas;

	my $slapd = eval { Test::OpenLDAP->new( suffix => $SUFFIX ) };
	return ( undef, "Test::OpenLDAP->new failed: $@" ) unless $slapd;

	# uri() carries the suffix as a path component; App::Nisaba just needs
	# scheme + encoded socket.
	my ($uri) = $slapd->uri =~ m{^(ldapi://[^/]+)};

	my $admin = Net::LDAP->new($uri);
	unless ($admin) {
		eval { $slapd->DESTROY };
		return ( undef, "could not connect to slapd at $uri: $@" );
	}
	my $mesg = $admin->bind( $slapd->admin_user, password => $slapd->admin_password );
	if ( $mesg->code ) {
		eval { $slapd->DESTROY };
		return ( undef, 'admin bind failed: ' . $mesg->error );
	}

	my $err = _load_schemas( $admin, $schema_dir, $repo_schemas );
	if ($err) {
		eval { $slapd->DESTROY };
		return ( undef, $err );
	}

	$err = _create_base_tree($admin);
	if ($err) {
		eval { $slapd->DESTROY };
		return ( undef, $err );
	}

	my %ini = (
		server       => $uri,
		port         => 389,                            # ignored for ldapi://
		bind         => $slapd->admin_user,
		pass         => $slapd->admin_password,
		userbase     => "ou=users,$SUFFIX",
		groupbase    => "ou=groups,$SUFFIX",
		oidcbase     => "ou=oidc,$SUFFIX",
		netgroupbase => "ou=netgroup,$SUFFIX",
		NSScheck     => 0,
		createHome   => 0,
		removeHome   => 0,
		%{ $opts{ini} // {} },
	);
	my $config = File::Temp->new( TEMPLATE => 'nisabarc-XXXXXX', TMPDIR => 1 );
	for my $key ( sort keys %ini ) {
		print $config "$key=$ini{$key}\n";
	}
	close $config;

	my $pt = eval { App::Nisaba->new( { config => $config->filename } ) };
	unless ($pt) {
		eval { $slapd->DESTROY };
		return ( undef, "App::Nisaba->new failed: $@" );
	}

	return (
		{
			pt     => $pt,
			slapd  => $slapd,
			admin  => $admin,
			uri    => $uri,
			config => $config,
		},
		undef
	);
} ## end sub setup

# Load the stock olc-format schema LDIFs and the repo's .schema files into
# cn=config over LDAP. Returns an error string, or '' on success.
sub _load_schemas {
	my ( $ldap, $schema_dir, $repo_schemas ) = @_;

	# Stock schemas, in dependency order.
	for my $name (qw(cosine inetorgperson nis)) {
		my $path = File::Spec->catfile( $schema_dir, "$name.ldif" );
		return "stock schema $path not found" unless -f $path;
		my $ldif = Net::LDAP::LDIF->new( $path, 'r', onerror => 'undef' );
		while ( my $entry = $ldif->read_entry ) {
			$entry->changetype('add');
			my $mesg = $ldap->add($entry);
			return "loading stock schema $name failed: " . $mesg->error if $mesg->code;
		}
	}

	# Repo schemas (slapd.conf format). openssh-lpk before the rest only by
	# convention; none of them depend on each other.
	for my $name (qw(openssh-lpk totp passkey oidc)) {
		my $path = File::Spec->catfile( $repo_schemas, "$name.schema" );
		return "repo schema $path not found" unless -f $path;
		my ( $at, $oc, $perr ) = _schema_file_to_olc($path);
		return "parsing $path failed: $perr" if $perr;
		my $cn   = $name;
		my $mesg = $ldap->add(
			"cn=$cn,cn=schema,cn=config",
			attrs => [
				objectClass => 'olcSchemaConfig',
				cn          => $cn,
				( @$at ? ( olcAttributeTypes => $at ) : () ),
				( @$oc ? ( olcObjectClasses  => $oc ) : () ),
			]
		);
		return "loading repo schema $name failed: " . $mesg->error if $mesg->code;
	}

	return '';
} ## end sub _load_schemas

# Convert a slapd.conf-format .schema file into lists of olcAttributeTypes /
# olcObjectClasses values. Handles only attributetype/objectclass directives
# (no objectidentifier macros — the repo schemas do not use them).
# Returns ( \@attribute_types, \@object_classes, $error ).
sub _schema_file_to_olc {
	my ($path) = @_;

	open my $fh, '<', $path or return ( undef, undef, "open failed: $!" );
	my $text = do { local $/; <$fh> };
	close $fh;

	return ( undef, undef, 'objectidentifier macros are not supported' )
		if $text =~ /^\s*objectidentifier\b/mi;

	$text =~ s/^\s*#.*$//mg;    # strip comments

	my ( @attrs, @ocs );
	while (
		$text =~ /\b(attributetype|objectclass)\s*
		          (\(.*?\))\s*
		          (?=\battributetype\b|\bobjectclass\b|\z)/sgix
		)
	{
		my ( $kind, $def ) = ( lc $1, $2 );
		$def =~ s/\s+/ /g;      # collapse continuation whitespace
		if   ( $kind eq 'attributetype' ) { push @attrs, $def }
		else                              { push @ocs,   $def }
	}

	return ( undef, undef, 'no attributetype/objectclass definitions found' )
		unless @attrs || @ocs;
	return ( \@attrs, \@ocs, '' );
} ## end sub _schema_file_to_olc

# Create the suffix entry and the OUs App::Nisaba's bases point at.
# Returns an error string, or '' on success.
sub _create_base_tree {
	my ($ldap) = @_;

	my @entries = (
		[ $SUFFIX, [ objectClass => [ 'dcObject', 'organization' ], dc => 'example', o => 'Example' ] ],
		map { [ "ou=$_,$SUFFIX", [ objectClass => 'organizationalUnit', ou => $_ ] ] }
			qw(users groups oidc netgroup),
	);
	for my $e (@entries) {
		my $mesg = $ldap->add( $e->[0], attrs => $e->[1] );
		return "adding $e->[0] failed: " . $mesg->error if $mesg->code;
	}
	return '';
}

sub teardown {
	my ($env) = @_;
	return unless $env;
	eval { $env->{admin}->unbind } if $env->{admin};
	eval { $env->{slapd}->DESTROY } if $env->{slapd};
}

1;
