#!perl

# Network-level security regression test for mojo_nisaba_sso (App::Nisaba::WebSSO).
# Boots the sso-fuzz target as a real prefork HTTP daemon (mock LDAP backend) and
# asserts it resists open redirect, LDAP injection, header injection, and
# parser-abuse (500 / connection-drop).
#
# Author/extended test: run with `prove -l xt/sso-fuzz.t`.

use strict;
use warnings;
use FindBin ();
use lib "$FindBin::Bin/lib";
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
} ## end BEGIN

use NisabaSSOFuzz;

my ( $ctx, $skip ) = NisabaSSOFuzz::boot_target( backend => 'mock', workers => 2 );
plan skip_all => "could not boot sso-fuzz target: $skip" unless $ctx;

diag("sso-fuzz mock target up at $ctx->{base} (pid $ctx->{pid})");
END { NisabaSSOFuzz::stop_target($ctx) if $ctx }

NisabaSSOFuzz::run_security_probes($ctx);

done_testing();
