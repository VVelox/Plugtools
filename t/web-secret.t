#!perl
use strict;
use warnings;
use Test::More;

eval { require App::Nisaba::WebSecret };
plan skip_all => "App::Nisaba::WebSecret failed to load: $@" if $@;

plan tests => 9;

# 1. configured value is used
is(
	App::Nisaba::WebSecret::resolve( configured => 'cfg', env => 'env' ),
	'cfg', 'configured websecret takes precedence over env',
);

# 2. env is used when configured is undef
is(
	App::Nisaba::WebSecret::resolve( configured => undef, env => 'env' ),
	'env', 'NISABA_SECRET used when websecret is not configured',
);

# 3. env is used when configured is empty string
is( App::Nisaba::WebSecret::resolve( configured => '', env => 'env' ), 'env', 'empty websecret falls through to env', );

# 4-5. no secret at all => dies
my $got = eval { App::Nisaba::WebSecret::resolve( configured => undef, env => undef ); 1 };
ok( !$got, 'resolve dies when no secret is available' );
like( $@, qr/Refusing to start/, 'die message explains the refusal' );

# 6. both empty => dies
$got = eval { App::Nisaba::WebSecret::resolve( configured => '', env => '' ); 1 };
ok( !$got, 'resolve dies when both sources are empty' );

# 7. the app name appears in the message
eval { App::Nisaba::WebSecret::resolve( configured => undef, env => undef, app => 'MyApp' ) };
like( $@, qr/MyApp/, 'app name is included in the die message' );

# 8. a whitespace/odd but non-empty secret is accepted verbatim (not our job to judge strength here)
is(
	App::Nisaba::WebSecret::resolve( configured => '   ', env => undef ),
	'   ', 'non-empty configured value is returned verbatim',
);

# 9. message points the operator at how to generate one
eval { App::Nisaba::WebSecret::resolve( configured => undef, env => undef ) };
like( $@, qr/NISABA_SECRET/, 'die message names the NISABA_SECRET env var' );
