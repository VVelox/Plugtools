#!perl -T

use Test::More tests => 1;

BEGIN {
	use_ok( 'App::Nisaba::Plugins::Dump' );
}

diag( "Testing App::Nisaba::Plugins::Dump $App::Nisaba::Plugins::Dump::VERSION, Perl $], $^X" );
