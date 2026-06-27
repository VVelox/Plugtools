#!perl -T

use Test::More tests => 1;

BEGIN {
	use_ok( 'App::Plugtools' );
}

diag( "Testing App::Plugtools $App::Plugtools::VERSION, Perl $], $^X" );
