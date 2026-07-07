#!perl -T

use strict;
use warnings;
use Test::More tests => 1;

BEGIN {
	use_ok('App::Nisaba');
}

diag("Testing App::Nisaba $App::Nisaba::VERSION, Perl $], $^X");
