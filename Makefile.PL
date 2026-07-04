use strict;
use warnings;
use ExtUtils::MakeMaker;
use File::ShareDir::Install;

install_share 'share';

my %WriteMakefileArgs = (
	NAME          => 'App::Nisaba',
	AUTHOR        => 'Zane C. Bowers <vvelox@vvelox.net>',
	VERSION_FROM  => 'lib/App/Nisaba.pm',
	ABSTRACT_FROM => 'lib/App/Nisaba.pm',
	( $ExtUtils::MakeMaker::VERSION >= 6.3002
		? ( 'LICENSE' => 'perl' )
		: () ),
	PL_FILES    => {},
	INST_SCRIPT => 'bin',
	EXE_FILES   => [
		'src_bin/plgadd', 'src_bin/plgclean', 'src_bin/plgmod',  'src_bin/plgrm',
		'src_bin/pluadd', 'src_bin/plumod',   'src_bin/plupass', 'src_bin/plurm',
		'src_bin/mojo_nisaba',
		'src_bin/mojo_nisaba_sso',
	],
	CONFIGURE_REQUIRES => {
		'ExtUtils::MakeMaker'     => '0',
		'File::ShareDir::Install' => '0',
	},
	TEST_REQUIRES => {
		'Test::More' => '0',
		'Crypt::JWT' => '0',
	},
	PREREQ_PM => {
		'Test::More'                        => 0,
		'File::BaseDir'                     => 0,
		'Config::IniHash'                   => 0,
		'Net::LDAP'                         => 0,
		'Net::LDAP::posixAccount'           => 0,
		'Net::LDAP::posixGroup'             => 0,
		'Term::ReadKey'                     => 0,
		'Net::LDAP::Extension::SetPassword' => 0,
		'String::ShellQuote'                => 0,
		'Data::Dumper'                      => 0,
		'Error::Helper'                     => '2.0.0',
		'Mojolicious'                       => '9.0',
		'File::ShareDir'                    => '1.0',
		'File::ShareDir::Install'           => '0.13',
		'Authen::TOTP'                      => 0,
		'Imager::QRCode'                    => 0,
		'CryptX'                            => 0,
		'DBI'                               => 0,
		'DBD::SQLite'                       => '1.50',
	},
	dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
	clean => { FILES    => 'App-Nisaba-*' },
);

# Compatibility with old versions of ExtUtils::MakeMaker
unless ( eval { ExtUtils::MakeMaker->VERSION('6.64'); 1 } ) {
	my $test_requires = delete $WriteMakefileArgs{TEST_REQUIRES} || {};
	@{ $WriteMakefileArgs{PREREQ_PM} }{ keys %$test_requires } = values %$test_requires;
}

unless ( eval { ExtUtils::MakeMaker->VERSION('6.55_03'); 1 } ) {
	my $build_requires = delete $WriteMakefileArgs{BUILD_REQUIRES} || {};
	@{ $WriteMakefileArgs{PREREQ_PM} }{ keys %$build_requires } = values %$build_requires;
}

delete $WriteMakefileArgs{CONFIGURE_REQUIRES}
	unless eval { ExtUtils::MakeMaker->VERSION('6.52'); 1 };
delete $WriteMakefileArgs{MIN_PERL_VERSION}
	unless eval { ExtUtils::MakeMaker->VERSION('6.48'); 1 };
delete $WriteMakefileArgs{LICENSE}
	unless eval { ExtUtils::MakeMaker->VERSION('6.31'); 1 };

WriteMakefile(%WriteMakefileArgs);

package MY;
use File::ShareDir::Install qw(postamble);
