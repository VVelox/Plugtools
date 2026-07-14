#!perl

# Same network-level security probes as xt/sso-fuzz.t, but against the sso-fuzz
# target backed by a REAL OpenLDAP (Test::OpenLDAP). This is the variant that can
# actually surface LDAP injection, which the mock backend cannot. Skips cleanly
# when slapd / Test::OpenLDAP are unavailable.
#
# Author/extended test: run with `prove -l xt/sso-fuzz-slapd.t`.

use strict;
use warnings;
use FindBin ();
use lib "$FindBin::Bin/lib";
use lib "$FindBin::Bin/../t/lib";    # NisabaSlapdTest
use Test::More;

BEGIN {
	eval { require Mojo::UserAgent; require Mojo::URL; 1 }
		or plan skip_all => "Mojolicious not available: $@";
	eval { require App::Nisaba::WebSSO; 1 }
		or plan skip_all => "App::Nisaba::WebSSO failed to load: $@";
	eval {
		require App::Nisaba::WebSSO::Storage;
		App::Nisaba::WebSSO::Storage->new( { backend => 'SQLite', path => ':memory:' } );
		1;
	}
		or plan skip_all => "App::Nisaba::WebSSO::Storage unavailable (DBD::SQLite?): $@";
	eval { require Test::OpenLDAP; 1 }
		or plan skip_all => "Test::OpenLDAP not available: $@";
	if ( my $reason = Test::OpenLDAP->skip ) {
		plan skip_all => "Test::OpenLDAP unusable: $reason";
	}
} ## end BEGIN

use NisabaSSOFuzz;

my ( $ctx, $skip ) = NisabaSSOFuzz::boot_target( backend => 'slapd', workers => 2 );
plan skip_all => "could not boot slapd-backed sso-fuzz target: $skip" unless $ctx;

diag("sso-fuzz slapd target up at $ctx->{base} (pid $ctx->{pid})");
END { NisabaSSOFuzz::stop_target($ctx) if $ctx }

NisabaSSOFuzz::run_security_probes($ctx);

done_testing();
