use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
	NAME          => 'Plugtools',
	AUTHOR        => 'Zane C. Bowers <vvelox@vvelox.net>',
	VERSION_FROM  => 'lib/Plugtools.pm',
	ABSTRACT_FROM => 'lib/Plugtools.pm',
	( $ExtUtils::MakeMaker::VERSION >= 6.3002
		? ( 'LICENSE' => 'perl' )
		: () ),
	PL_FILES    => {},
	INST_SCRIPT => 'bin',
	EXE_FILES   => [
		'src_bin/plgadd', 'src_bin/plgclean', 'src_bin/plgmod',  'src_bin/plgrm',
		'src_bin/pluadd', 'src_bin/plumod',   'src_bin/plupass', 'src_bin/plurm',
	],
	PREREQ_PM => {
		'Test::More'                        => 0,
		'File::BaseDir'                     => 0,
		'Config::IniHash'                   => 0,
		'Sys::User::UIDhelper'              => 0,
		'Sys::Group::GIDhelper'             => 0,
		'Net::LDAP'                         => 0,
		'Net::LDAP::posixAccount'           => 0,
		'Net::LDAP::posixGroup'             => 0,
		'Term::ReadKey'                     => 0,
		'Net::LDAP::Extension::SetPassword' => 0,
		'String::ShellQuote'                => 0,
		'Data::Dumper'                      => 0,
		'Error::Helper'                     => '2.0.0',
	},
	dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
	clean => { FILES    => 'Plugtools-*' },
);
