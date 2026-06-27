#!perl -T

use Test::More tests => 1;

BEGIN {
	use_ok( 'App::Plugtools::Plugins::Dump' );
}

diag( "Testing App::Plugtools::Plugins::Dump $App::Plugtools::Plugins::Dump::VERSION, Perl $], $^X" );
