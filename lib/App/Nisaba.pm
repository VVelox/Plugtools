package App::Nisaba;

use warnings;
use strict;
use Config::IniHash;
use File::BaseDir qw/xdg_config_home/;
use Sys::User::UIDhelper;
use Sys::Group::GIDhelper;
use Net::LDAP;
use Net::LDAP::Entry;
use Net::LDAP::posixAccount;
use Net::LDAP::posixGroup;
use Net::LDAP::nisNetgroup;
use String::ShellQuote;
use Net::LDAP::Extension::SetPassword;
use Net::SMTP;
use Authen::TOTP;
use Imager;
use Imager::QRCode;
use MIME::Base64 qw(encode_base64);
use base 'Error::Helper';

=encoding utf8

=head1 NAME

App::Nisaba - LDAP and Posix

=head1 VERSION

Version 1.3.0

=cut

our $VERSION = '1.3.0';

=head1 SYNOPSIS

    use App::Nisaba;

    my $pt = App::Nisaba->new();
    ...

=head1 METHODS

=head2 new

Initiate App::Nisaba.

Only one arguement is accepted and that is a hash.

=head3 args hash

At this time, none of these values are required.

=head4 config

This specifies a config file to read other than the default.

    #initilize it and read the default config
    my $pt=App::Nisaba->new();

    #initilize it and read '/some/config'
    my $pt=App::Nisaba->new({ config=>'/some/config' });

=cut

sub new {
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	my $self = {
		perror        => undef,
		error         => undef,
		errorLine     => undef,
		errorFilename => undef,
		errorString   => '',
		errorExtra    => {
			all_errors_fatal => 1,
			flags            => {
				1  => 'readConfigFailed',
				2  => 'missingRequired',
				3  => 'noFreeUID',
				4  => 'noFreeGID',
				5  => 'noUser',
				6  => 'noGroup',
				7  => 'UIDnotNumeric',
				8  => 'GIDnotNumeric',
				9  => 'userExists',
				10 => 'groupExists',
				11 => 'ldapConnectFailed',
				12 => 'posixGroupFailed',
				13 => 'ldapBindFailed',
				14 => 'groupNotFound',
				15 => 'groupNotInLDAP',
				16 => 'groupDeleteFailed',
				17 => 'userNotFound',
				18 => 'userNotInLDAP',
				19 => 'addEntryFailed',
				20 => 'GIDexists',
				21 => 'createHomeFailed',
				22 => 'skelCopyFailed',
				23 => 'chownFailed',
				24 => 'chmodFailed',
				25 => 'removeMemberFailed',
				26 => 'removeHomeFailed',
				27 => 'fetchGroupsFailed',
				28 => 'noGID',
				29 => 'updateGIDfailed',
				30 => 'noUID',
				31 => 'updateUIDfailed',
				32 => 'fetchUserFailed',
				33 => 'noGECOS',
				34 => 'updateFailed',
				35 => 'noPassword',
				36 => 'setPasswordFailed',
				37 => 'fetchUsersFailed',
				38 => 'noLDAP',
				39 => 'noPluginDo',
				40 => 'pluginConfigMissing',
				41 => 'pluginExecFailed',
				42 => 'noLDAPentry',
				43 => 'entryNotLDAPEntry',
				44 => 'ldapNotLDAP',
				45 => 'pluginError',
				46 => 'updateAfterPassFailed',
				47 => 'noShell',
				48 => 'noHome',
				49 => 'noMail',
				50 => 'noTelephoneNumber',
				51 => 'noMobile',
				52 => 'noTitle',
				53 => 'noRoomNumber',
				54 => 'noEmployeeNumber',
				55 => 'noEmployeeType',
				56 => 'noPreferredLanguage',
				57 => 'noLabeledURI',
				58 => 'noSN',
				59 => 'noGivenName',
				60 => 'noDescription',
				61 => 'noPostalAddress',
				62 => 'noHomePostalAddress',
				63 => 'noDisplayName',
				64 => 'alreadyInetOrgPerson',
				66 => 'netgroupbaseNotConfigured',
				67 => 'noNetgroupName',
				68 => 'noTripleSpecified',
				69 => 'noMemberSpecified',
				70 => 'noCN',
				71 => 'lastCN',
				72 => 'noLdapPublicKeySchema',
				73 => 'noSSHPublicKey',
				74 => 'alreadyLdapPublicKey',
				75 => 'authFailed',
				76 => 'smtpNotConfigured',
				77 => 'smtpConnectionFailed',
				78 => 'smtpSendFailed',
				79 => 'noTotpSchema',
				80 => 'alreadyTotpUser',
				81 => 'noTotpSecret',
				82 => 'invalidTotpStatus',
				83 => 'noTotpScratchCode',
				84 => 'alreadyMfaGroup',
				85 => 'noMfaGracePeriod',
				86 => 'invalidTotpAlgorithm',
				87 => 'invalidTotpDigits',
				88 => 'invalidTotpPeriod',
				89 => 'totpScratchCodeLimitReached',
			},
			fatal_flags      => {},
			perror_not_fatal => 0,
		},
	};
	bless $self;

	if ( !defined( $args{config} ) ) {
		$args{config} = xdg_config_home() . '/nisabarc';
	}

	$self->readConfig( $args{config} );

	return $self;
} ## end sub new

=head2 addGroup

=head3 args hash

=head4 group

This is the group name to add.

=head4 gid

This is the numeric ID of the group to add. If it is
not defined, it will automatically be added.

=head4 dump

If this is true, call the dump method on the create Net::LDAP::Entry object.

    #the most basic form
    $pt->addGroup({
                   group=>'someGroup',
                   })

    #do more
    $pt->addGroup({
                   group=>'someGroup',
                   gid=>'4444',
                   dump=>'1',
                   })

=cut

sub addGroup {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	#error if we don't have a group name
	if ( !defined( $args{group} ) ) {
		$self->{error}       = 6;
		$self->{errorString} = 'No group name specified';
		$self->warn;
		return undef;
	}

	#error if the user already exists
	my ( $gname, $gpasswd, $gid, $members ) = getgrnam( $args{group} );
	if ( defined($gname) ) {
		$self->{error}       = 10;
		$self->{errorString} = 'The group "' . $args{group} . '" already exists';
		$self->warn;
		return undef;
	}

	#if we don't have a GID, find the first free one
	if ( !defined( $args{gid} ) ) {
		my $gidhelper = Sys::Group::GIDhelper->new( { min => $self->{ini}->{''}->{GIDstart} } );
		my $gid       = $gidhelper->firstfree();
		if ( !defined($gid) ) {
			$self->{error}       = 4;
			$self->{errorString} = 'Could not locate a free GID';
			$self->warn;
			return undef;
		}
		$args{gid} = $gid;
	} ## end if ( !defined( $args{gid} ) )

	( $gname, $gpasswd, $gid, $members ) = getgrnam( $args{gid} );
	if ( defined($gid) ) {
		$self->{error}       = 20;
		$self->{errorString} = 'The GID "' . $args{gid} . '" already exists.';
		$self->warn;
		return undef;
	}

	#make sure the GID is complete numeric
	if ( !( $args{gid} =~ /^[0123456789]*$/ ) ) {
		$self->{error}       = 8;
		$self->{errorString} = 'The specified GID, "' . $args{gid} . '", is not numeric';
		$self->warn;
		return undef;
	}

	#initiates the Net::LDAP::posixAccount
	my $entrycreator = Net::LDAP::posixGroup->new( { baseDN => $self->{ini}->{''}->{groupbase} } );
	if ( ( !defined($entrycreator) ) || ( defined( $entrycreator->{error} ) ) ) {
		$self->{error} = 12;
		if ( !defined($entrycreator) ) {
			$self->{errorString} = 'Net::LDAP::posixGroup->create returned a undefined object';
		} else {
			$self->{errorString}
				= 'Net::LDAP::posixGroup->create errored. error="'
				. $entrycreator->{error}
				. '" errorString="'
				. $entrycreator->{errorString} . '"';
		}
		$self->warn;
		return undef;
	} ## end if ( ( !defined($entrycreator) ) || ( defined...))
	my $entry = $entrycreator->create(
		{
			name    => $args{group},
			gid     => $args{gid},
			primary => $self->{ini}->{''}->{groupPrimary},
		}
	);
	if ( defined( $entrycreator->{error} ) ) {
		$self->{error} = 12;
		$self->{errorString}
			= 'Net::LDAP::posixGroup->create errored. error="'
			. $entrycreator->{error}
			. '" errorString="'
			. $entrycreator->{errorString} . '"';
		$self->warn;
		return undef;
	} ## end if ( defined( $entrycreator->{error} ) )

	#dump it if asked
	if ( $args{dump} ) {
		$entry->dump;
	}

	#connect to the LDAP server
	my $ldap = $self->connect();

	#call a plugin if needed
	if ( defined( $self->{ini}->{''}->{pluginAddGroup} ) ) {
		$self->plugin(
			{
				ldap  => $ldap,
				entry => $entry,
				do    => 'pluginAddGroup',
			},
			\%args
		);
	} ## end if ( defined( $self->{ini}->{''}->{pluginAddGroup...}))

	#add it
	my $mesg = $entry->update($ldap);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 19;
		$self->{errorString} = '$entry->update($ldap) failed. $mesg->{errorMessage}="' . $mesg->{errorMessage} . '"';
		$self->warn;
		return undef;
	}

	return 1;
} ## end sub addGroup

=head2 addUser

=head3 args hash

=head4 user

The user to create.

=head4 uid

The numeric user ID for the new user. If this is note defined,
the first free one will be used.

=head4 group

The primary group of user. If this is not defined, the username is
used. If the user is this is not defined, it will be set to the same
as the user.

=head4 gid

If this is defined, the specified GID will be used instead of automatically
assigning one.

=head4 gecos

The gecos field for the user. If this is not defined, it is set to
the user name.

=head4 shell

This is the shell for the user. If this is not defined, the default
one is used.

=head4 home

This is the home directory for the user. If this is not defined, the
home prototype is used.

=head4 createHome

If this is specified, the default value for createHome will be overrode the
defaults or what is specified in the config.

If it exists, it assumes it does not need to be created, but it will still be
chowned.

=head4 skel

Use this instead of the default skeleton or the one specified in the config file.

This is skipped, if the home already exists.

=head4 chmodValue

Overrides the default value for this or the one specified in the config.

=head4 chmodHome

Overrides the default value for this or the one specified in the config.

=head4 chownHome

If home should be chowned. This overrides the value specified in the
config or the default one.

=head4 dump

If this is true, call the dump method on the create Net::LDAP::Entry object.

    #the most basic form
    $pt->addUser({
                  user=>'someUser',
                  })

    #do more
    $pt->addUser({
                  user=>'someUser',
                  uid=>'3333',
                  group=>'someGroup',
                  gid=>'4444',
                  dump=>'1',
                   })

=cut

sub addUser {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	#error if no user has been specified
	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	#error if the user already exists
	my ( $name, $passwd, $uid, $gid, $quota, $comment, $gcos, $dir, $shell, $expire ) = getpwnam( $args{user} );
	if ( defined($name) ) {
		$self->{error}       = 9;
		$self->{errorString} = 'The user "' . $args{user} . '" already exists';
		$self->warn;
		return undef;
	}

	#make sure we have gecos
	if ( !defined( $args{gecos} ) ) {
		$args{gecos} = $args{user};
	}

	#make sure we have a shell
	if ( !defined( $args{shell} ) ) {
		$args{shell} = $self->{ini}->{''}->{defaultShell};
	}

	#make sure we have a group name
	if ( !defined( $args{group} ) ) {
		$args{group} = $args{user};
	}

	#makes sure the UID is defined
	if ( !defined( $args{uid} ) ) {
		#gets it if it not defined
		my $uidhelper = Sys::User::UIDhelper->new(
			{
				min => $self->{ini}->{''}->{UIDstart}
			}
		);
		my $uid = $uidhelper->firstfree();
		if ( !defined($uid) ) {
			$self->{error}       = 3;
			$self->{errorString} = 'Could not locate a free UID';
			$self->warn;
			return undef;
		}
		$args{uid} = $uid;
	} ## end if ( !defined( $args{uid} ) )

	#make sure the UID is complete numeric
	if ( !( $args{uid} =~ /^[0123456789]*$/ ) ) {
		$self->{error}       = 7;
		$self->{errorString} = 'The specified UID, "' . $args{uid} . '", is not numeric';
		$self->warn;
		return undef;
	}

	#check if the group exists or not
	my ( $gname, $gpasswd, $ggid, $members ) = getgrnam( $args{group} );
	if ( !defined($gname) ) {
		$self->addGroup(
			{
				group => $args{group},
				gid   => $args{gid},
				dump  => $args{dump},
			}
		);
	}

	#gets the GID
	( $gname, $gpasswd, $args{gid}, $members ) = getgrnam( $args{group} );

	#build the user
	$args{home} = $self->{ini}->{''}->{HOMEproto};
	$args{home} =~ s/\%\%USERNAME\%\%/$args{user}/g;

	#initiates the Net::LDAP::posixAccount
	my $entrycreator = Net::LDAP::posixAccount->new( { baseDN => $self->{ini}->{''}->{userbase} } );
	my $entry        = $entrycreator->create(
		{
			name       => $args{user},
			uid        => $args{uid},
			gid        => $args{gid},
			home       => $args{home},
			loginShell => $args{shell},
			primary    => $self->{ini}->{''}->{userPrimary},
		}
	);

	#connect to the LDAP server
	my $ldap = $self->connect();

	#call a plugin if needed
	if ( defined( $self->{ini}->{''}->{pluginAddUser} ) ) {
		$self->plugin(
			{
				ldap  => $ldap,
				entry => $entry,
				do    => 'pluginAddUser',
			},
			\%args
		);
	} ## end if ( defined( $self->{ini}->{''}->{pluginAddUser...}))

	#add it
	my $mesg = $entry->update($ldap);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 19;
		$self->{errorString} = '$entry->update($ldap) failed. $mesg->{errorMessage}="' . $mesg->{errorMessage} . '"';
		$self->warn;
		return undef;
	}

	#dump it if needed
	if ( $args{dump} ) {
		$entry->dump;
	}

	#create the home directory if needed, after getting the required values
	if ( !defined( $args{createHome} ) ) {
		$args{createHome} = $self->{ini}->{''}->{createHome};
	}
	if ( !defined( $args{skel} ) ) {
		$args{skel} = $self->{ini}->{''}->{skeletonHome};
	}
	if ( !defined( $args{chownHome} ) ) {
		$args{chownHome} = $self->{ini}->{''}->{chownHome};
	}
	if ( !defined( $args{chmodHome} ) ) {
		$args{chmodHome} = $self->{ini}->{''}->{chmodHome};
	}
	if ( !defined( $args{chmodValue} ) ) {
		$args{chmodValue} = $self->{ini}->{''}->{chmodValue};
	}
	if ( $args{createHome} ) {
		if ( !-e $args{home} ) {
			#copy it
			system( 'cp -r ' . shell_quote( $args{skel} ) . ' ' . shell_quote( $args{home} ) );
			if ( $? ne '0' ) {
				$self->{error}       = 22;
				$self->{errorString} = 'Copying home from "' . $args{skel} . '" to "' . $args{home} . '" failed';
				$self->warn;
				return undef;
			}

			#chown it if needed
			if ( $args{chownHome} ) {
				system(   'chown -R '
						. shell_quote( $args{user} ) . ':'
						. shell_quote( $args{group} ) . ' '
						. shell_quote( $args{home} ) );
				if ( $? ne '0' ) {
					$self->{error}       = 23;
					$self->{errorString} = 'Chowning "' . $args{home} . '" to "' . $args{chmodValue} . '" failed';
					$self->warn;
					return undef;
				}
			} ## end if ( $args{chownHome} )

			#chmod it if needed
			if ( $args{chmodHome} ) {
				system( 'chmod -R ' . shell_quote( $args{chmodValue} ) . ' ' . shell_quote( $args{home} ) );
				if ( $? ne '0' ) {
					$self->{error}       = 24;
					$self->{errorString} = 'Chmoding "' . $args{home} . '" to "' . $args{chmodValue} . '" failed';
					$self->warn;
					return undef;
				}
			}
		} ## end if ( !-e $args{home} )
	} ## end if ( $args{createHome} )

	return 1;
} ## end sub addUser

=head2 connect

This forms a LDAP connection using the information in
config file.

    my $ldap=$pt->connect;

=cut

sub connect {
	my $self = $_[0];

	$self->errorblank;

	#try to connect
	my $ldap = Net::LDAP->new( $self->{ini}->{''}->{server}, port => $self->{ini}->{''}->{port} );

	#check if it connected or not
	if ( !$ldap ) {
		$self->{error}       = 11;
		$self->{errorString} = 'Failed to connect to LDAP';
		$self->warn;
		return undef;
	}

	#start TLS if it is needed
	my $mesg;
	if ( $self->{ini}->{''}->{starttls} ) {
		$mesg = $ldap->start_tls(
			verify     => $self->{ini}->{''}->{TLSverify},
			sslversion => $self->{ini}->{''}->{SSLversion},
			ciphers    => $self->{ini}->{''}->{SSLciphers},
		);

		if ( $mesg->{errorMessage} ne '' ) {
			$self->{error}       = 13;
			$self->{errorString} = '$ldap->start_tls failed. $mesg->{errorMessage}="' . $mesg->{errorMessage} . '"';
			$self->warn;
			return undef;
		}
	} ## end if ( $self->{ini}->{''}->{starttls} )

	#bind
	$mesg = $ldap->bind( $self->{ini}->{''}->{bind}, password => $self->{ini}->{''}->{pass}, );
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error} = 13;
		$self->{errorString}
			= 'Binding to the LDAP server failed. $mesg->{errorMessage}="' . $mesg->{errorMessage} . '"';
		$self->warn;
		return undef;
	}

	return $ldap;
} ## end sub connect

=head2 deleteGroup

This removes a group.

    $pt->deleteGroup('someGroup');

=cut

sub deleteGroup {
	my $self  = $_[0];
	my $group = $_[1];

	$self->errorblank;

	#error if we don't have a group name
	if ( !defined($group) ) {
		$self->{error}       = 6;
		$self->{errorString} = 'No group name specified';
		$self->warn;
		return undef;
	}

	#error if the user does not exists
	my ( $gname, $gpasswd, $gid, $members ) = getgrnam($group);
	if ( !defined($gname) ) {
		$self->{error}       = 10;
		$self->{errorString} = 'The group "' . $group . '" does not exist';
		$self->warn;
		return undef;
	}

	#connect to the LDAP server
	my $ldap = $self->connect();

	#search and get the first entry
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{groupbase},
		filter => '(&(cn=' . $group . ') (gidNumber=' . $gid . '))'
	);
	my $entry = $mesg->pop_entry;

	#if $entry is not defined or does not exist under the specified base
	if ( !defined($entry) ) {
		$self->{error} = 15;
		$self->{errorString}
			= 'The group "'
			. $group
			. '" does not exist in specified group base, "'
			. $self->{ini}->{''}->{groupbase} . '", ';
		$self->warn;
		return undef;
	} ## end if ( !defined($entry) )

	#call a plugin if needed
	if ( defined( $self->{ini}->{''}->{pluginDeleteGroup} ) ) {
		$self->plugin(
			{
				ldap  => $ldap,
				entry => $entry,
				do    => 'pluginDeleteGroup',
			},
			{
				group => $group,
			}
		);
	} ## end if ( defined( $self->{ini}->{''}->{pluginDeleteGroup...}))

	#delete the entry
	$entry->delete();
	$mesg = $entry->update($ldap);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error} = 13;
		$self->{errorString}
			= 'Deleting entry "' . $entry->dn . '" failed. $mesg->{errorMessage}="' . $mesg->{errorMessage} . '"';
		$self->warn;
		return undef;
	}

	return 1;
} ## end sub deleteGroup

=head2 deleteUser

This removes a user.

Only LDAP is touched at this time, so if a user is a member of a group
setup in '/etc/groups', then it won't be removed from that group.

This does not remove the user's old home directory.

=head3 arge hash

'user' is the only required value.

=head4 user

This is the user to be removed.

=head4 removeHome

This removes the home directory of the user.

=head4 removeGroup

Remove the primary group if it is empty.

    #the most basic form
    $pt->deleteUser({
                  user=>'someUser',
                  })

    #do more
    $pt->deleteUser({
                     user=>'someUser',
                     removeHome=>'1',
                     removeGroup=>'0',
                     })

=cut

sub deleteUser {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	#make sure a group if specifed
	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	#error if the user already exists
	my ( $name, $passwd, $uid, $gid, $quota, $comment, $gcos, $dir, $shell, $expire ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exists';
		$self->warn;
		return undef;
	}

	#check if the group exists or not
	my ( $gname, $gpasswd, $ggid, $members ) = getgrgid($gid);
	my $removeGroup = 0;
	#set the group to be removed if it exists
	if ( defined($ggid) ) {
		$removeGroup = 1;
	}

	#connect to the LDAP server
	my $ldap = $self->connect();

	#search and get the first entry
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	my $entry = $mesg->pop_entry;

	#if $entry is not defined or does not exist under the specified base
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "'
			. $args{user}
			. '" does not exist in specified group base, "'
			. $self->{ini}->{''}->{userbase} . '", ';
		$self->warn;
		return undef;
	} ## end if ( !defined($entry) )

	#we check this here as checking it after wards after deleting the user does not work
	my $onlyMember;
	if ( !defined( $args{removeGroup} ) ) {
		$args{removeGroup} = $self->{ini}->{''}->{removeGroup};
	}
	if ( $args{removeGroup} ) {
		#check if it the only member of that group
		$onlyMember = $self->onlyMember(
			{
				user  => $args{user},
				group => $gname,
			}
		);
	}

	#call a plugin if needed
	if ( defined( $self->{ini}->{''}->{pluginDeleteUser} ) ) {
		$self->plugin(
			{
				ldap  => $ldap,
				entry => $entry,
				do    => 'pluginDeleteUser',
			},
			\%args
		);
	} ## end if ( defined( $self->{ini}->{''}->{pluginDeleteUser...}))

	#delete the entry
	$entry->delete();
	$mesg = $entry->update($ldap);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error} = 13;
		$self->{errorString}
			= 'Deleting entry "' . $entry->dn . '" failed. $mesg->{errorMessage}="' . $mesg->{errorMessage} . '"';
		$self->warn;
		return undef;
	}

	#remove the primary group if requested...
	if ( $args{removeGroup} ) {
		#proceede further if it is the only member
		if ($onlyMember) {
			#figure out if it is a LDAP group or not
			my $returned = $self->isLDAPgroup($gname);
			#if it is a LDAP group, remove it
			if ($returned) {
				$self->deleteGroup($gname);
			}
		}
	} ## end if ( $args{removeGroup} )

	#remove the user from what ever groups they are in, in LDAP
	$self->removeUserFromGroups( $args{user} );

	#remove the primary group if requested...
	if ( !defined( $args{removeHome} ) ) {
		$args{removeHome} = $self->{ini}->{''}->{removeHome};
	}
	if ( $args{removeHome} ) {
		system( 'rm -rf ' . shell_quote($dir) );
		if ( $? ne '0' ) {
			$self->{error}       = 26;
			$self->{errorString} = 'rm -rf ' . shell_quote($dir) . ' has failed failed';
			$self->warn;
			return undef;
		}
	}

	return 1;
} ## end sub deleteUser

=head2 findGroupDN

This locates a DN for a already setup group.

    my $dn=$pt->findGroupDN('someGroup');

=cut

sub findGroupDN {
	my $self  = $_[0];
	my $group = $_[1];

	$self->errorblank;

	#make sure a group if specifed
	if ( !defined($group) ) {
		$self->{error}       = 6;
		$self->{errorString} = 'No group name specified';
		$self->warn;
		return undef;
	}

	#error if the user does not exists
	my ( $gname, $gpasswd, $gid, $members ) = getgrnam($group);
	if ( !defined($gname) ) {
		$self->{error}       = 14;
		$self->{errorString} = 'The group "' . $group . '" does not exist';
		$self->warn;
		return undef;
	}

	#connect to the LDAP server
	my $ldap = $self->connect();

	#search and get the first entry
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{groupbase},
		filter => '(&(cn=' . $group . ') (gidNumber=' . $gid . '))'
	);
	my $entry = $mesg->pop_entry;

	#if $entry is not defined or does not exist under the specified base
	if ( !defined($entry) ) {
		$self->{error} = 15;
		$self->{errorString}
			= 'The group "'
			. $group
			. '" does not exist in specified group base, "'
			. $self->{ini}->{''}->{groupbase} . '", ';
		$self->warn;
		return undef;
	} ## end if ( !defined($entry) )

	#if we get here, it means we have a entry... thus we have a DN
	return $entry->dn;
} ## end sub findGroupDN

=head2 findUserDN

This locates a DN for a already setup group.

    my $dn=$pt->findUserDN('someUser');

=cut

sub findUserDN {
	my $self = $_[0];
	my $user = $_[1];

	$self->errorblank;

	#make sure a group if specifed
	if ( !defined($user) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	#error if the user already exists
	my ( $name, $passwd, $uid, $gid, $quota, $comment, $gcos, $dir, $shell, $expire ) = getpwnam($user);
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $user . '" does not exists';
		$self->warn;
		return undef;
	}

	#connect to the LDAP server
	my $ldap = $self->connect();

	#search and get the first entry
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $user . ') (uidNumber=' . $uid . '))'
	);
	my $entry = $mesg->pop_entry;

	#if $entry is not defined or does not exist under the specified base
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "'
			. $user
			. '" does not exist in specified group base, "'
			. $self->{ini}->{''}->{userbase} . '", ';
		$self->warn;
		return undef;
	} ## end if ( !defined($entry) )

	#if we get here, it means we have a entry... thus we have a DN
	return $entry->dn;
} ## end sub findUserDN

=head2 getUserEntry

Fetch a Net::LDAP::Entry object of a user.

=head3 args hash

=head4 user

This is the user to fetch a Net::LDAP::Entry
of.

    my $entry=$pt->getUserEntry({
                                 user=>'someUser',
                                 });

=cut

sub getUserEntry {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	#error if we don't have a group name
	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	#error if the user already exists
	my ( $name, $passwd, $uid, $gid, $quota, $comment, $gecos, $dir, $shell, $expire ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exists';
		$self->warn;
		return undef;
	}

	#connect to the LDAP server
	my $ldap = $self->connect();

	#search and get the first entry
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error} = 32;
		$self->{errorString}
			= 'Fetching the entry for the user failed under "'
			. $self->{ini}->{''}->{userbase} . '"'
			. $mesg->{errorMessage} . '"';
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;

	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "'
			. $args{user}
			. '" was not found under'
			. 'the base "'
			. $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	} ## end if ( !defined($entry) )

	return $entry;
} ## end sub getUserEntry

=head2 groupAddUser

This adds a user from a group.

=head3 args hash

=head4 group

The group to act on.

=head4 user

The user to act remove from the group.

=head4 dump

Call the dump method on the entry afterwards.

    $pt->groupAddUser({
                       group=>'someGroup',
                       user=>'someUser',
                       })

=cut

sub groupAddUser {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	#error if we don't have a group name
	if ( !defined( $args{group} ) ) {
		$self->{error}       = 6;
		$self->{errorString} = 'No group name specified';
		$self->warn;
		return undef;
	}

	#error if no user has been specified
	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	#error if the user does not exists
	my ( $gname, $gpasswd, $gid, $members ) = getgrnam( $args{group} );
	if ( !defined($gname) ) {
		$self->{error}       = 14;
		$self->{errorString} = 'The group "' . $args{group} . '" does not exist';
		$self->warn;
		return undef;
	}

	#connect to the LDAP server
	my $ldap = $self->connect();

	#search and get the first entry
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{groupbase},
		filter => '(&(cn=' . $args{group} . ') (gidNumber=' . $gid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error} = 27;
		$self->{errorString}
			= 'Fetching a list of posixGroup objects under "'
			. $self->{ini}->{''}->{groupbase} . '"'
			. $mesg->{errorMessage} . '"';
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;

	#if $entry is not defined or does not exist under the specified base
	if ( !defined($entry) ) {
		$self->{error} = 15;
		$self->{errorString}
			= 'The group "'
			. $args{group}
			. '" does not exist in specified group base, "'
			. $self->{ini}->{''}->{groupbase} . '", ';
		$self->warn;
		return undef;
	} ## end if ( !defined($entry) )

	$entry->add( memberUid => $args{user} );

	#call a plugin if needed
	if ( defined( $self->{ini}->{''}->{pluginGroupAddUser} ) ) {
		$self->plugin(
			{
				ldap  => $ldap,
				entry => $entry,
				do    => 'pluginGroupAddUser',
			},
			\%args
		);
	} ## end if ( defined( $self->{ini}->{''}->{pluginGroupAddUser...}))

	#update the entry
	my $mesg2 = $entry->update($ldap);
	if ( $mesg2->{errorMessage} ne '' ) {
		$self->{error} = 13;
		$self->{errorString}
			= 'Adding the user, "'
			. $args{user}
			. '", to  "'
			. $entry->dn
			. '" failed. $mesg2->{errorMessage}="'
			. $mesg2->{errorMessage} . '"';
		$self->warn;
		return undef;
	} ## end if ( $mesg2->{errorMessage} ne '' )

	#dump the entry if asked
	if ( $args{dump} ) {
		$entry->dump;
	}

	return 1;
} ## end sub groupAddUser

=head2 groupGIDchange

This changes the GID for a group.

=head3 args hash

=head4 group

The group to act on.

=head4 gid

The GID to change this group to.

=head4 userUpdate

Update any user that has the old GID as their primary GID. This defaults to
true, '1'.

=head4 dump

Call the dump method on the group afterwards.

    $pt->groupGIDchange({
                         group=>'someGroup',
                         gid=>'2222',
                         })


=cut

sub groupGIDchange {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	#error if we don't have a group name
	if ( !defined( $args{group} ) ) {
		$self->{error}       = 6;
		$self->{errorString} = 'No group name specified';
		$self->warn;
		return undef;
	}

	#error if no user has been specified
	if ( !defined( $args{gid} ) ) {
		$self->{error}       = 28;
		$self->{errorString} = 'No GID specified';
		$self->warn;
		return undef;
	}

	#make sure the GID is complete numeric
	if ( !( $args{gid} =~ /^[0123456789]*$/ ) ) {
		$self->{error}       = 8;
		$self->{errorString} = 'The specified GID, "' . $args{gid} . '", is not numeric';
		$self->warn;
		return undef;
	}

	#error if the user does not exists
	my ( $gname, $gpasswd, $gid, $members ) = getgrnam( $args{group} );
	if ( !defined($gname) ) {
		$self->{error}       = 14;
		$self->{errorString} = 'The group "' . $args{group} . '" does not exist';
		$self->warn;
		return undef;
	}

	#connect to the LDAP server
	my $ldap = $self->connect();

	#search and get the first entry
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{groupbase},
		filter => '(&(cn=' . $args{group} . ') (gidNumber=' . $gid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error} = 27;
		$self->{errorString}
			= 'Fetching a list of posixGroup objects under "'
			. $self->{ini}->{''}->{groupbase} . '"'
			. $mesg->{errorMessage} . '"';
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;

	#if $entry is not defined or does not exist under the specified base
	if ( !defined($entry) ) {
		$self->{error} = 15;
		$self->{errorString}
			= 'The group "'
			. $args{group}
			. '" does not exist in specified group base, "'
			. $self->{ini}->{''}->{groupbase} . '", ';
		$self->warn;
		return undef;
	} ## end if ( !defined($entry) )

	$entry->delete( gidNumber => $gid );
	$entry->add( gidNumber => $args{gid} );

	#call a plugin if needed
	if ( defined( $self->{ini}->{''}->{pluginGroupGIDchange} ) ) {
		$self->plugin(
			{
				ldap  => $ldap,
				entry => $entry,
				do    => 'pluginGroupGIDchange',
			},
			\%args
		);
	} ## end if ( defined( $self->{ini}->{''}->{pluginGroupGIDchange...}))

	#update the entry
	my $mesg2 = $entry->update($ldap);
	if ( $mesg2->{errorMessage} ne '' ) {
		$self->{error} = 29;
		$self->{errorString}
			= 'Updating the GID from "'
			. $gid
			. '" to "'
			. $args{gid}
			. '" for "'
			. $entry->dn
			. '" failed. $mesg2->{errorMEssage}="'
			. $mesg2->{errorMessage} . '"';
		$self->warn;
		return undef;
	} ## end if ( $mesg2->{errorMessage} ne '' )

	#dump the entry if asked
	if ( $args{dump} ) {
		$entry->dump;
	}

	#return successfully now if don't have to update any possible users
	if ( !defined( $args{userUpdate} ) ) {
		$args{userUpdate} = $self->{ini}->{''}->{userUpdate};
	}
	if ( !$args{userUpdate} ) {
		return 1;
	}

	#we now do another search for the purpose of updating any users with the old GID
	my $mesg3 = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(objectClass=posixAccount) (gidNumber=' . $gid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error} = 37;
		$self->{errorString}
			= 'The search for posixAccounts entries that need updating failed. base="'
			. $self->{ini}->{''}->{userbase}
			. '" $mesg3->{errorMessage}="'
			. $mesg3->{errorMessage} . '"';
		$self->warn;
		return undef;
	} ## end if ( $mesg->{errorMessage} ne '' )
	$entry = $mesg3->pop_entry;

	#if no entries are found, nothing needs updated
	if ( !defined($entry) ) {
		return 1;
	}

	#go through each one and update it
	my $loop = 1;
	while ($loop) {
		$entry->delete( 'gidNumber' => $gid );
		$entry->add( gidNumber => $args{gid} );

		#update the entry
		my $mesg4 = $entry->update($ldap);
		if ( $mesg2->{errorMessage} ne '' ) {
			$self->{error} = 29;
			$self->{errorString}
				= 'Changing the GID to "'
				. $args{gid}
				. '" from "'
				. $gid
				. '" for  "'
				. $entry->dn
				. '" failed. $mesg4->{errorMessage}="'
				. $mesg4->{errorMessage} . '"';
			$self->warn;
			return undef;
		} ## end if ( $mesg2->{errorMessage} ne '' )

		#dump the entry if asked
		if ( $args{dump} ) {
			$entry->dump;
		}

		#get the next entry and decide it it should continue or not
		$entry = $mesg3->pop_entry;
		if ( !defined($entry) ) {
			$loop = 0;
		}
	} ## end while ($loop)

	return 1;
} ## end sub groupGIDchange

=head2 groupDescriptionChange

Sets the C<description> attribute of a posixGroup entry to a single value,
replacing any existing value. Pass an empty string or omit C<description> to
clear the attribute entirely.

=head3 args hash

=head4 group

The group to act on.

=head4 description

The new description. Pass an empty string to clear.

    $pt->groupDescriptionChange({ group => 'someGroup', description => 'A description' });

=cut

sub groupDescriptionChange {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{group} ) ) {
		$self->{error}       = 6;
		$self->{errorString} = 'No group name specified';
		$self->warn;
		return undef;
	}

	my ( $gname, $gpasswd, $gid ) = getgrnam( $args{group} );
	if ( !defined($gname) ) {
		$self->{error}       = 14;
		$self->{errorString} = 'The group "' . $args{group} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{groupbase},
		filter => '(&(cn=' . $args{group} . ')(gidNumber=' . $gid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 27;
		$self->{errorString} = 'Fetching group "' . $args{group} . '" failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}

	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error}       = 15;
		$self->{errorString} = 'Group "' . $args{group} . '" not found under "' . $self->{ini}->{''}->{groupbase} . '"';
		$self->warn;
		return undef;
	}

	my $new_desc = $args{description} // '';
	if ( $new_desc eq '' ) {
		$entry->delete('description');
	} else {
		$entry->replace( description => $new_desc );
	}

	my $update = $entry->update($ldap);
	if ( $update->code ) {
		$self->{error}       = 34;
		$self->{errorString} = 'Updating description on "' . $entry->dn . '" failed: ' . $update->error;
		$self->warn;
		return undef;
	}

	return 1;
} ## end sub groupDescriptionChange

=head2 groupRemoveUser

This removes a user from a group.

=head3 args hash

=head4 group

The group to act on.

=head4 user

The user to act remove from the group.

=head4 dump

Call the dump method on the group afterwards.

    $pt->groupRemoveUser({
                       group=>'someGroup',
                       user=>'someUser',
                       })

=cut

sub groupRemoveUser {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	#error if we don't have a group name
	if ( !defined( $args{group} ) ) {
		$self->{error}       = 6;
		$self->{errorString} = 'No group name specified';
		$self->warn;
		return undef;
	}

	#error if no user has been specified
	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	#error if the user does not exists
	my ( $gname, $gpasswd, $gid, $members ) = getgrnam( $args{group} );
	if ( !defined($gname) ) {
		$self->{error}       = 14;
		$self->{errorString} = 'The group "' . $args{group} . '" does not exist';
		$self->warn;
		return undef;
	}

	#connect to the LDAP server
	my $ldap = $self->connect();

	#search and get the first entry
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{groupbase},
		filter => '(&(cn=' . $args{group} . ') (gidNumber=' . $gid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error} = 27;
		$self->{errorString}
			= 'Fetching a list of posixGroup objects under "'
			. $self->{ini}->{''}->{groupbase} . '"'
			. $mesg->{errorMessage} . '"';
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;

	#if $entry is not defined or does not exist under the specified base
	if ( !defined($entry) ) {
		$self->{error} = 15;
		$self->{errorString}
			= 'The group "'
			. $args{group}
			. '" does not exist in specified group base, "'
			. $self->{ini}->{''}->{groupbase} . '", ';
		$self->warn;
		return undef;
	} ## end if ( !defined($entry) )

	$entry->delete( memberUid => $args{user} );

	#call a plugin if needed
	if ( defined( $self->{ini}->{''}->{pluginGroupRemoveUser} ) ) {
		$self->plugin(
			{
				ldap  => $ldap,
				entry => $entry,
				do    => 'pluginGroupRemoveUser',
			},
			\%args
		);
	} ## end if ( defined( $self->{ini}->{''}->{pluginGroupRemoveUser...}))

	#update the entry
	my $mesg2 = $entry->update($ldap);
	if ( $mesg2->{errorMessage} ne '' ) {
		$self->{error} = 13;
		$self->{errorString}
			= 'Removing the user, "'
			. $args{user}
			. '", from  "'
			. $entry->dn
			. '" failed. $mesg2->{errorMessage}="'
			. $mesg2->{errorMessage} . '"';
		$self->warn;
		return undef;
	} ## end if ( $mesg2->{errorMessage} ne '' )

	#dump the entry if asked
	if ( $args{dump} ) {
		$entry->dump;
	}

	return 1;
} ## end sub groupRemoveUser

=head2 groupClean

This checks through the groups setup in LDAP and removes any group that does not exist.

=head3 args hash

=head4 dump

If this is specified, the dump method is called on any updated entry. If this is not
defined, it defaults to false.

    $pt->groupClean;

    #do the same thing as above, but do $entry->dump for any changed entry
    $pt->groupClean({dump=>'1'});

=cut

sub groupClean {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	#connect to the LDAP server
	my $ldap = $self->connect();

	#search and get the first entry
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{groupbase},
		filter => '(objectClass=posixGroup)',
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error} = 27;
		$self->{errorString}
			= 'Fetching a list of posixGroup objects under "'
			. $self->{ini}->{''}->{groupbase} . '"'
			. $mesg->{errorMessage} . '"';
		$self->warn;
		return undef;
	}

	#get the first entry
	my $entry = $mesg->pop_entry;

	#if the entry is not defined, there are no groups
	if ( !defined($entry) ) {
		return 1;
	}

	#process each one
	my $loop = 1;
	while ($loop) {
		my @members = $entry->get_value('memberUid');
		#if there is no $members[0], it means the group
		#has no members listed
		if ( defined( $members[0] ) ) {
			my $int     = 0;
			my $changed = 0;    #records if any changes have happened or not
			while ( defined( $members[$int] ) ) {
				my ( $name, $passwd, $uid, $gid, $quota, $comment, $gcos, $dir, $shell, $expire )
					= getpwnam( $members[$int] );
				#if it is not defined, it means the user does not exist
				if ( !defined($name) ) {
					$entry->delete( 'memberUid' => $members[$int] );
					$changed = 1;
				}

				$int++;
			} ## end while ( defined( $members[$int] ) )

			#if it changed, update it
			if ($changed) {
				my $mesg2 = $entry->update($ldap);
				if ( $mesg->{errorMessage} ne '' ) {
					$self->{error} = 28;
					$self->{errorString}
						= 'Failed to update the entry, "'
						. $entry->dn
						. '". $mesg2->{errorMessage}="'
						. $mesg2->{errorMessage} . '"';
					$self->warn;
					return undef;
				} ## end if ( $mesg->{errorMessage} ne '' )
				if ( $args{dump} ) {
					$entry->dump;
				}
			} ## end if ($changed)
		} ## end if ( defined( $members[0] ) )

		#get the next entry
		$entry = $mesg->pop_entry;
		#exit this loop if it is not defined... meaning we reached the end
		if ( !defined($entry) ) {
			$loop = 0;
		}
	} ## end while ($loop)

	return 1;
} ## end sub groupClean

=head2 getGroups

Returns all posixGroup entries found in LDAP under the configured group base.

Returns an array ref of L<Net::LDAP::Entry> objects, or an empty array ref if
no groups exist. Each entry provides the standard posixGroup attributes such
as C<cn>, C<gidNumber>, and C<memberUid>.

    my $groups = $pt->getGroups;
    for my $entry (@{$groups}) {
        printf "%-20s %s\n", $entry->get_value('cn'), $entry->get_value('gidNumber');
    }

=cut

sub getGroups {
	my $self = $_[0];

	$self->errorblank;

	my $ldap = $self->connect();

	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{groupbase},
		filter => '(objectClass=posixGroup)',
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error} = 27;
		$self->{errorString}
			= 'Fetching posixGroup objects under "'
			. $self->{ini}->{''}->{groupbase}
			. '" failed. '
			. $mesg->{errorMessage};
		$self->warn;
		return undef;
	} ## end if ( $mesg->{errorMessage} ne '' )

	my @groups;
	my $entry = $mesg->pop_entry;
	while ( defined($entry) ) {
		push @groups, $entry;
		$entry = $mesg->pop_entry;
	}

	return \@groups;
} ## end sub getGroups

=head2 getUsers

Returns all posixAccount entries found in LDAP under the configured user base.

Returns an array ref of L<Net::LDAP::Entry> objects, or an empty array ref if
no users exist. Each entry provides the standard posixAccount attributes such
as C<uid>, C<uidNumber>, C<gidNumber>, C<homeDirectory>, C<loginShell>, and
C<gecos>.

    my $users = $pt->getUsers;
    for my $entry (@{$users}) {
        printf "%-20s %s\n", $entry->get_value('uid'), $entry->get_value('uidNumber');
    }

=cut

sub getUsers {
	my $self = $_[0];

	$self->errorblank;

	my $ldap = $self->connect();

	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(objectClass=posixAccount)',
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error} = 37;
		$self->{errorString}
			= 'Fetching posixAccount objects under "'
			. $self->{ini}->{''}->{userbase}
			. '" failed. '
			. $mesg->{errorMessage};
		$self->warn;
		return undef;
	} ## end if ( $mesg->{errorMessage} ne '' )

	my @users;
	my $entry = $mesg->pop_entry;
	while ( defined($entry) ) {
		push @users, $entry;
		$entry = $mesg->pop_entry;
	}

	return \@users;
} ## end sub getUsers

=head2 isLDAPgroup

This tests if a group is in LDAP or not.

    my $returned=$pt->isLDAPgroup('someGroup');
    if($returned){
        print "Yes!\n";
    }else{
        print "No!\n";
    }

=cut

sub isLDAPgroup {
	my $self  = $_[0];
	my $group = $_[1];

	$self->errorblank;

	#make sure a group if specifed
	if ( !defined($group) ) {
		$self->{error}       = 6;
		$self->{errorString} = 'No group name specified';
		$self->warn;
		return undef;
	}

	#error if the user does not exists
	my ( $gname, $gpasswd, $gid, $members ) = getgrnam($group);
	if ( !defined($gname) ) {
		$self->{error}       = 10;
		$self->{errorString} = 'The group "' . $group . '" does not exist';
		$self->warn;
		return undef;
	}

	#connect to the LDAP server
	my $ldap = $self->connect();

	#search and get the first entry
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{groupbase},
		filter => '(&(cn=' . $group . ') (gidNumber=' . $gid . '))'
	);
	my $entry = $mesg->pop_entry;

	#if $entry is not defined or does not exist under the specified base
	if ( !defined($entry) ) {
		return undef;
	}

	return 1;
} ## end sub isLDAPgroup

=head2 isLDAPuser

This tests if a group is in LDAP or not.

    my $returned=$pt->isLDAPuser('someUser');
    if($returned){
        print "Yes!\n";
    }else{
        print "No!\n";
    }

=cut

sub isLDAPuser {
	my $self = $_[0];
	my $user = $_[1];

	$self->errorblank;

	#make sure a group if specifed
	if ( !defined($user) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	#error if the user already exists
	my ( $name, $passwd, $uid, $gid, $quota, $comment, $gcos, $dir, $shell, $expire ) = getpwnam($user);
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $user . '" does not exists';
		$self->warn;
		return undef;
	}

	#connect to the LDAP server
	my $ldap = $self->connect();

	#search and get the first entry
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $user . ') (uidNumber=' . $uid . '))'
	);
	my $entry = $mesg->pop_entry;

	#if $entry is not defined or does not exist under the specified base
	if ( !defined($entry) ) {
		return undef;
	}

	return 1;
} ## end sub isLDAPuser

=head2 onlyMember

This figures out if a user is the only member of a group.

This returns true if the user is the only member of that group. A value
of false means that user is not in that group and there are no members or
that it that there are other members.

=head3 args hash

Both 'user' and 'group' are required.

=head4 user

This is the user it is checking to see if it is the only member of a
group.

=head4 group

This is the group to check.

    my $returned=$pt->onlyMember({
                       user=>'someUser',
                       group=>'someGroup',
                       });


=cut

sub onlyMember {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	#error is no group is specified
	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified.';
		$self->warn;
		return undef;
	}

	#error is no group is specified
	if ( !defined( $args{group} ) ) {
		$self->{error}       = 6;
		$self->{errorString} = 'No group name specified.';
		$self->warn;
		return undef;
	}

	#error if the user already exists
	my ( $gname, $gpasswd, $ggid, $members ) = getgrnam( $args{group} );
	if ( !defined($gname) ) {
		$self->{error}       = 14;
		$self->{errorString} = 'The group "' . $args{group} . '" does not exist';
		$self->warn;
		return undef;
	}

	#error if the user already exists
	my ( $name, $passwd, $uid, $gid, $quota, $comment, $gcos, $dir, $shell, $expire ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exists';
		$self->warn;
		return undef;
	}

	#break the list of members apart
	my @membersA = split( /,/, $members );

	#handle it if there are no group members
	if ( !defined( $membersA[0] ) ) {
		#if the group's GID and the user's primary GID are the same
		#here then it means the user is not explicityly as a member of that group
		if ( $ggid eq $gid ) {
			return 1;
		}

		#if we get here, the group has no explicityly listed members
		#and the user is not a member of the group
		return undef;
	} ## end if ( !defined( $membersA[0] ) )

	#check each member to see if it is not the user in question
	#while this may seem stupid, there is a possibiltiy that the user
	#has been listed in a group more than once...
	my $int = 0;
	while ( defined( $membersA[$int] ) ) {
		if ( $membersA[$int] ne $args{user} ) {
			return undef;
		}

		$int++;
	}

	return 1;
} ## end sub onlyMember

=head2 plugin

This processes series plugins.

=head3 opts hash

This is the first required hash.

=head4 ldap

This is the current LDAP connect.

=head4 do

This contains the variable it should reference for what plugins to run.

=head4 entry

This is the LDAP entry to work on.

=head3 args hash

This is the hash that was passed to the function calling the plugin.

=cut

sub plugin {
	my $self = $_[0];
	my $opts;
	my %opts;
	if ( defined( $_[1] ) ) {
		%opts = %{ $_[1] };
	}
	my %args;
	if ( defined( $_[2] ) ) {
		%args = %{ $_[2] };
	}

	$self->errorblank;

	#error if no LDAP connection is present
	if ( !defined( $opts{ldap} ) ) {
		$self->{error}       = 38;
		$self->{errorString} = 'No LDAP connection passed';
		$self->warn;
		return undef;
	}

	#error if no LDAP connection is present
	if ( !defined( $opts{do} ) ) {
		$self->{error}       = 39;
		$self->{errorString} = 'What selection of plugins to process has not been specified. $opts{do} is undefined';
		$self->warn;
		return undef;
	}

	#error if no LDAP connection is present
	if ( !defined( $opts{entry} ) ) {
		$self->{error}       = 42;
		$self->{errorString} = 'No Net::LDAP::Entry passed. $opts{entry} is undefined';
		$self->warn;
		return undef;
	}

	#error if the LDAP entry that is specified is not a Net::LDAP::Entry object
	if ( ref( $opts{entry} ) ne 'Net::LDAP::Entry' ) {
		$self->{error}       = 43;
		$self->{errorString} = '$opts{entry} is not a Net::LDAP::Entry object';
		$self->warn;
		return undef;
	}

	#error if no entry connection is present
	if ( ref( $opts{ldap} ) ne 'Net::LDAP' ) {
		$self->{error}       = 44;
		$self->{errorString} = '$opts{ldap} is not a Net::LDAP object';
		$self->warn;
		return undef;
	}

	#
	$opts{self} = $self;

	#make sure the specified config exists
	if ( !defined( $self->{ini}->{''}->{ $opts{do} } ) ) {
		$self->{error}       = 40;
		$self->{errorString} = 'The variable "' . $opts{do} . '" does not exist in the config';
		$self->warn;
		return undef;
	}

	#split the plugin apart
	my @plugins = split( /,/, $self->{ini}->{''}->{ $opts{do} } );

	#process each one
	my $int = 0;
	while ( defined( $plugins[$int] ) ) {
		my %returned;
		my $run = 'use ' . $plugins[$int] . ';' . "\n" . 'my %returned=' . $plugins[$int] . '->plugin(\%opts, \%args);';

		#run it
		my $ran = eval($run);

		#If we did not get a boolean true, then it failed
		if ( !$ran ) {
			$self->{error}       = 41;
			$self->{errorString} = 'Executing the plugin "' . $plugins[$int] . '" failed. $run="' . $run . '"';
			$self->warn;
			return undef;
		}

		#it errored...
		if ( $returned{error} ) {
			$self->{error} = 45;
			$self->{errorString}
				= 'The plugin returned a error. $returned{error}="'
				. $returned{error} . '" '
				. '$returned{errorString}="'
				. $returned{errorString} . '"';
			$self->warn;
			return undef;
		} ## end if ( $returned{error} )

		$int++;
	} ## end while ( defined( $plugins[$int] ) )

	return 1;
} ## end sub plugin

=head2 removeUserFromGroups

This removes a user from any group in LDAP they are a member of.

No checks are made to see if the user exists or not.

    $pt->removeUserFromGroups('someUser');

=cut

sub removeUserFromGroups {
	my $self = $_[0];
	my $user = $_[1];

	$self->errorblank;

	#make sure a group if specifed
	if ( !defined($user) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	#connect to the LDAP server
	my $ldap = $self->connect();

	#search and get the first entry
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{groupbase},
		filter => '(&(objectClass=posixGroup) (memberUid=' . $user . '))'
	);
	my $entry = $mesg->pop_entry;

	#no groups with this user in them were found
	if ( !defined($entry) ) {
		return 1;
	}

	#exit it
	my $loop = 1;
	while ($loop) {
		#remove the memberUid attribute that is equal to the user in question and update it
		$entry->delete( 'memberUid' => $user );
		my $mesg2 = $entry->update($ldap);
		#handles any errors
		if ( $mesg2->{errorMessage} ne '' ) {
			$self->{error} = 25;
			$self->{errorString}
				= 'Deleting memberUid='
				. $user
				. ' from the entry "'
				. $entry->dn
				. '" failed. $mesg2->{errorMessage}="'
				. $mesg2->{errorMessage} . '"';
			$self->warn;
			return undef;
		} ## end if ( $mesg2->{errorMessage} ne '' )

		#get the next entry
		$entry = $mesg->pop_entry;
		#if the next entry is not defined, there are no more so we exit the loop
		if ( !defined($entry) ) {
			$loop = 0;
		}
	} ## end while ($loop)

	return 1;
} ## end sub removeUserFromGroups

=head2 netgroupbaseConfigured

Returns true if a non-empty C<netgroupbase> is set in the configuration,
false otherwise.  Use this to guard UI elements before calling any netgroup
method.

    if ( $pt->netgroupbaseConfigured ) { ... }

=cut

sub netgroupbaseConfigured {
	my $self = $_[0];
	return ( defined( $self->{ini}->{''}->{netgroupbase} ) && $self->{ini}->{''}->{netgroupbase} ne '' )
		? 1
		: 0;
}

=head2 addNetgroup

Creates a new nisNetgroup entry in LDAP.

=head3 args hash

=head4 group

The netgroup name to create. Required.

=head4 triples

An optional arrayref of nisNetgroupTriple strings, e.g. C<["(host,user,domain)"]>.

=head4 members

An optional arrayref of memberNisNetgroup names.

=head4 description

An optional description string.

    $pt->addNetgroup({ group => 'someNetgroup', triples => ['(,,example.com)'] });

=cut

sub addNetgroup {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{group} ) ) {
		$self->{error}       = 67;
		$self->{errorString} = 'No netgroup name specified';
		$self->warn;
		return undef;
	}

	if ( $self->{ini}->{''}->{netgroupbase} eq '' ) {
		$self->{error}       = 66;
		$self->{errorString} = 'netgroupbase not configured';
		$self->warn;
		return undef;
	}

	my $creator = Net::LDAP::nisNetgroup->new( baseDN => $self->{ini}->{''}->{netgroupbase} );
	if ( !defined($creator) ) {
		$self->{error}       = 12;
		$self->{errorString} = 'Net::LDAP::nisNetgroup->new returned undef: ' . ( Net::LDAP::nisNetgroup->error // '' );
		$self->warn;
		return undef;
	}

	my %create_args = (
		name    => $args{group},
		triples => $args{triples} // [],
		members => $args{members} // [],
	);
	if ( defined( $args{description} ) && $args{description} ne '' ) {
		$create_args{description} = $args{description};
	}

	my $entry = $creator->create(%create_args);
	if ( !defined($entry) ) {
		$self->{error}       = 12;
		$self->{errorString} = 'Net::LDAP::nisNetgroup->create returned undef: ' . ( $creator->errorString // '' );
		$self->warn;
		return undef;
	}

	my $ldap     = $self->connect();
	my $add_mesg = $ldap->add($entry);
	if ( $add_mesg->code ) {
		$self->{error}       = 19;
		$self->{errorString} = 'Adding netgroup entry failed: ' . $add_mesg->error;
		$self->warn;
		return undef;
	}

	return 1;
} ## end sub addNetgroup

=head2 deleteNetgroup

Deletes a nisNetgroup entry from LDAP.

=head3 args hash

=head4 group

The netgroup name to delete. Required.

    $pt->deleteNetgroup({ group => 'someNetgroup' });

=cut

sub deleteNetgroup {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{group} ) ) {
		$self->{error}       = 67;
		$self->{errorString} = 'No netgroup name specified';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{netgroupbase},
		filter => '(&(objectClass=nisNetgroup)(cn=' . $args{group} . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 27;
		$self->{errorString} = 'Searching for netgroup "' . $args{group} . '" failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}

	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error}       = 15;
		$self->{errorString} = 'Netgroup not found: ' . $args{group};
		$self->warn;
		return undef;
	}

	my $del_mesg = $ldap->delete( $entry->dn );
	if ( $del_mesg->code ) {
		$self->{error}       = 16;
		$self->{errorString} = 'Deleting netgroup "' . $args{group} . '" failed: ' . $del_mesg->error;
		$self->warn;
		return undef;
	}

	return 1;
} ## end sub deleteNetgroup

=head2 getNetgroups

Returns an arrayref of all nisNetgroup Net::LDAP::Entry objects found under
the configured netgroupbase.

Returns an empty arrayref if none exist.

    my $netgroups = $pt->getNetgroups;

=cut

sub getNetgroups {
	my $self = $_[0];

	$self->errorblank;

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{netgroupbase},
		filter => '(objectClass=nisNetgroup)'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error} = 27;
		$self->{errorString}
			= 'Fetching nisNetgroup objects under "'
			. $self->{ini}->{''}->{netgroupbase}
			. '" failed: '
			. $mesg->{errorMessage};
		$self->warn;
		return undef;
	} ## end if ( $mesg->{errorMessage} ne '' )

	my @entries;
	my $entry = $mesg->pop_entry;
	while ( defined($entry) ) {
		push @entries, $entry;
		$entry = $mesg->pop_entry;
	}

	return \@entries;
} ## end sub getNetgroups

=head2 getNetgroupEntry

Returns a single Net::LDAP::Entry for the named nisNetgroup.

=head3 args hash

=head4 group

The netgroup name to look up. Required.

    my $entry = $pt->getNetgroupEntry({ group => 'someNetgroup' });

=cut

sub getNetgroupEntry {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{group} ) ) {
		$self->{error}       = 67;
		$self->{errorString} = 'No netgroup name specified';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{netgroupbase},
		filter => '(&(objectClass=nisNetgroup)(cn=' . $args{group} . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 27;
		$self->{errorString} = 'Searching for netgroup "' . $args{group} . '" failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}

	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error}       = 15;
		$self->{errorString} = 'Netgroup not found: ' . $args{group};
		$self->warn;
		return undef;
	}

	return $entry;
} ## end sub getNetgroupEntry

=head2 netgroupDescriptionChange

Sets or clears the description attribute on a nisNetgroup entry.
Pass an empty string or omit description to clear.

=head3 args hash

=head4 group

The netgroup name to act on. Required.

=head4 description

The new description. Pass an empty string to clear.

    $pt->netgroupDescriptionChange({ group => 'someNetgroup', description => 'A description' });

=cut

sub netgroupDescriptionChange {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{group} ) ) {
		$self->{error}       = 67;
		$self->{errorString} = 'No netgroup name specified';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{netgroupbase},
		filter => '(&(objectClass=nisNetgroup)(cn=' . $args{group} . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 27;
		$self->{errorString} = 'Searching for netgroup "' . $args{group} . '" failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}

	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error}       = 15;
		$self->{errorString} = 'Netgroup not found: ' . $args{group};
		$self->warn;
		return undef;
	}

	my $new_desc = $args{description} // '';
	if ( $new_desc eq '' ) {
		$entry->delete('description');
	} else {
		$entry->replace( description => $new_desc );
	}

	my $update = $entry->update($ldap);
	if ( $update->code ) {
		$self->{error}       = 34;
		$self->{errorString} = 'Updating description on "' . $entry->dn . '" failed: ' . $update->error;
		$self->warn;
		return undef;
	}

	return 1;
} ## end sub netgroupDescriptionChange

=head2 netgroupTripleAdd

Adds a nisNetgroupTriple value to a nisNetgroup entry.

=head3 args hash

=head4 group

The netgroup name to act on. Required.

=head4 triple

The triple string to add, e.g. C<"(host,user,domain)">. Required.

    $pt->netgroupTripleAdd({ group => 'someNetgroup', triple => '(,,example.com)' });

=cut

sub netgroupTripleAdd {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{group} ) ) {
		$self->{error}       = 67;
		$self->{errorString} = 'No netgroup name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{triple} ) ) {
		$self->{error}       = 68;
		$self->{errorString} = 'No triple specified';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{netgroupbase},
		filter => '(&(objectClass=nisNetgroup)(cn=' . $args{group} . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 27;
		$self->{errorString} = 'Searching for netgroup "' . $args{group} . '" failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}

	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error}       = 15;
		$self->{errorString} = 'Netgroup not found: ' . $args{group};
		$self->warn;
		return undef;
	}

	$entry->add( nisNetgroupTriple => $args{triple} );

	my $update = $entry->update($ldap);
	if ( $update->code ) {
		$self->{error}       = 34;
		$self->{errorString} = 'Adding triple to "' . $entry->dn . '" failed: ' . $update->error;
		$self->warn;
		return undef;
	}

	return 1;
} ## end sub netgroupTripleAdd

=head2 netgroupTripleRemove

Removes a nisNetgroupTriple value from a nisNetgroup entry.

=head3 args hash

=head4 group

The netgroup name to act on. Required.

=head4 triple

The triple string to remove. Required.

    $pt->netgroupTripleRemove({ group => 'someNetgroup', triple => '(,,example.com)' });

=cut

sub netgroupTripleRemove {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{group} ) ) {
		$self->{error}       = 67;
		$self->{errorString} = 'No netgroup name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{triple} ) ) {
		$self->{error}       = 68;
		$self->{errorString} = 'No triple specified';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{netgroupbase},
		filter => '(&(objectClass=nisNetgroup)(cn=' . $args{group} . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 27;
		$self->{errorString} = 'Searching for netgroup "' . $args{group} . '" failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}

	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error}       = 15;
		$self->{errorString} = 'Netgroup not found: ' . $args{group};
		$self->warn;
		return undef;
	}

	$entry->delete( nisNetgroupTriple => [ $args{triple} ] );

	my $update = $entry->update($ldap);
	if ( $update->code ) {
		$self->{error}       = 34;
		$self->{errorString} = 'Removing triple from "' . $entry->dn . '" failed: ' . $update->error;
		$self->warn;
		return undef;
	}

	return 1;
} ## end sub netgroupTripleRemove

=head2 netgroupMemberAdd

Adds a memberNisNetgroup value to a nisNetgroup entry.

=head3 args hash

=head4 group

The netgroup name to act on. Required.

=head4 member

The netgroup name to add as a member. Required.

    $pt->netgroupMemberAdd({ group => 'someNetgroup', member => 'otherNetgroup' });

=cut

sub netgroupMemberAdd {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{group} ) ) {
		$self->{error}       = 67;
		$self->{errorString} = 'No netgroup name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{member} ) ) {
		$self->{error}       = 69;
		$self->{errorString} = 'No member specified';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{netgroupbase},
		filter => '(&(objectClass=nisNetgroup)(cn=' . $args{group} . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 27;
		$self->{errorString} = 'Searching for netgroup "' . $args{group} . '" failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}

	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error}       = 15;
		$self->{errorString} = 'Netgroup not found: ' . $args{group};
		$self->warn;
		return undef;
	}

	$entry->add( memberNisNetgroup => $args{member} );

	my $update = $entry->update($ldap);
	if ( $update->code ) {
		$self->{error}       = 34;
		$self->{errorString} = 'Adding member to "' . $entry->dn . '" failed: ' . $update->error;
		$self->warn;
		return undef;
	}

	return 1;
} ## end sub netgroupMemberAdd

=head2 netgroupMemberRemove

Removes a memberNisNetgroup value from a nisNetgroup entry.

=head3 args hash

=head4 group

The netgroup name to act on. Required.

=head4 member

The netgroup name to remove. Required.

    $pt->netgroupMemberRemove({ group => 'someNetgroup', member => 'otherNetgroup' });

=cut

sub netgroupMemberRemove {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{group} ) ) {
		$self->{error}       = 67;
		$self->{errorString} = 'No netgroup name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{member} ) ) {
		$self->{error}       = 69;
		$self->{errorString} = 'No member specified';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{netgroupbase},
		filter => '(&(objectClass=nisNetgroup)(cn=' . $args{group} . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 27;
		$self->{errorString} = 'Searching for netgroup "' . $args{group} . '" failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}

	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error}       = 15;
		$self->{errorString} = 'Netgroup not found: ' . $args{group};
		$self->warn;
		return undef;
	}

	$entry->delete( memberNisNetgroup => [ $args{member} ] );

	my $update = $entry->update($ldap);
	if ( $update->code ) {
		$self->{error}       = 34;
		$self->{errorString} = 'Removing member from "' . $entry->dn . '" failed: ' . $update->error;
		$self->warn;
		return undef;
	}

	return 1;
} ## end sub netgroupMemberRemove

=head2 readConfig

This reads the specified config.

    #reads the default config
    $pt->readConfig();

    #reads the config '/some/config'
    $pt->readConfig('/some/config');

=cut

sub readConfig {
	my $self   = $_[0];
	my $config = $_[1];

	$self->errorblank;

	#if it is not defined, use the default one
	if ( !defined($config) ) {
		$config = xdg_config_home() . '/nisabarc';
	}

	#reads the config
	my $ini = ReadINI($config);

	#errors if it is not defined... meaning it errored
	if ( !defined($ini) ) {
		$self->{error}       = 1;
		$self->{errorString} = 'Failed to read the config';
		$self->warn;
		return undef;
	}

	#puts together a array to check for the required ones
	my @required;
	push( @required, 'bind' );
	push( @required, 'pass' );
	push( @required, 'userbase' );
	push( @required, 'groupbase' );

	#make sure they are all defined
	my $int = 0;
	while ( defined( $required[$int] ) ) {
		#error if it is not defined
		if ( !defined( $ini->{''}->{ $required[$int] } ) ) {
			$self->{error} = 2;
			$self->{errorString}
				= 'The required variable "' . $required[$int] . '" is not defined in the config, "' . $config . '",';
			$self->warn;
			return undef;
		}

		$int++;
	} ## end while ( defined( $required[$int] ) )

	#define the defaults if they are not defined
	if ( !defined( $ini->{''}->{UIDstart} ) ) {
		$ini->{''}->{UIDstart} = '1001';
	}
	if ( !defined( $ini->{''}->{GIDstart} ) ) {
		$ini->{''}->{GIDstart} = '1001';
	}
	if ( !defined( $ini->{''}->{defaultShell} ) ) {
		$ini->{''}->{defaultShell} = '/bin/tcsh';
	}
	if ( !defined( $ini->{''}->{HOMEproto} ) ) {
		$ini->{''}->{HOMEproto} = '/home/%%USERNAME%%/';
	}
	if ( !defined( $ini->{''}->{skeletonHome} ) ) {
		$ini->{''}->{skeletonHome} = '/etc/skel/';
	}
	if ( !defined( $ini->{''}->{chmodValue} ) ) {
		$ini->{''}->{chmodValue} = '640';
	}
	if ( !defined( $ini->{''}->{chmodHome} ) ) {
		$ini->{''}->{chmodHome} = '1';
	}
	if ( !defined( $ini->{''}->{chownHome} ) ) {
		$ini->{''}->{chownHome} = '1';
	}
	if ( !defined( $ini->{''}->{createHome} ) ) {
		$ini->{''}->{createHome} = '1';
	}
	if ( !defined( $ini->{''}->{groupPrimary} ) ) {
		$ini->{''}->{groupPrimary} = 'cn';
	}
	if ( !defined( $ini->{''}->{userPrimary} ) ) {
		$ini->{''}->{userPrimary} = 'uid';
	}
	if ( !defined( $ini->{''}->{server} ) ) {
		$ini->{''}->{server} = '127.0.0.1';
	}
	if ( !defined( $ini->{''}->{port} ) ) {
		$ini->{''}->{port} = '389';
	}
	if ( !defined( $ini->{''}->{TLSverify} ) ) {
		$ini->{''}->{TLSverify} = 'none';
	}
	if ( !defined( $ini->{''}->{SSLversion} ) ) {
		$ini->{''}->{SSLversion} = 'tlsv1';
	}
	if ( !defined( $ini->{''}->{SSLciphers} ) ) {
		$ini->{''}->{SSLciphers} = 'ALL';
	}
	if ( !defined( $ini->{''}->{removeHome} ) ) {
		$ini->{''}->{removeHome} = '0';
	}
	if ( !defined( $ini->{''}->{removeGroup} ) ) {
		$ini->{''}->{removeGroup} = '1';
	}
	if ( !defined( $ini->{''}->{userUpdate} ) ) {
		$ini->{''}->{userUpdate} = '1';
	}
	if ( !defined( $ini->{''}->{netgroupbase} ) ) {
		$ini->{''}->{netgroupbase} = '';
	}
	if ( !defined( $ini->{''}->{websecret} ) ) {
		$ini->{''}->{websecret} = 'nisaba_change_me';
	}
	if ( !defined( $ini->{''}->{totpissuer} ) ) {
		$ini->{''}->{totpissuer} = 'Nisaba';
	}
	if ( !defined( $ini->{''}->{totpAdminAddScratchCodes} ) ) {
		$ini->{''}->{totpAdminAddScratchCodes} = 0;
	}
	if ( !defined( $ini->{''}->{totpMaxScratchCodes} ) ) {
		$ini->{''}->{totpMaxScratchCodes} = 10;
	}
	if ( !defined( $ini->{''}->{smtpserver} ) ) {
		$ini->{''}->{smtpserver} = '';
	}
	if ( !defined( $ini->{''}->{smtpfrom} ) ) {
		$ini->{''}->{smtpfrom} = '';
	}
	if ( !defined( $ini->{''}->{smtpport} ) ) {
		$ini->{''}->{smtpport} = '25';
	}
	if ( !defined( $ini->{''}->{smtpuser} ) ) {
		$ini->{''}->{smtpuser} = '';
	}
	if ( !defined( $ini->{''}->{smtppass} ) ) {
		$ini->{''}->{smtppass} = '';
	}
	if ( !defined( $ini->{''}->{smtptls} ) ) {
		$ini->{''}->{smtptls} = '';
	}

	#if we get here, the ini is good... so we save it
	$self->{ini} = $ini;

	return 1;
} ## end sub readConfig

=head2 userGECOSchange

This changes the UID for a user.

=head3 args hash

=head4 user

The user to act on.

=head4 gecos

The GECOS to change this user to.

=head4 dump

Call the dump method on the group afterwards.

    $pt->userGECOSchange({
                          user=>'someUser',
                          gecos=>'whatever',
                          });

=cut

sub userGECOSchange {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	#error if we don't have a group name
	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	#error if no user has been specified
	if ( !defined( $args{gecos} ) ) {
		$self->{error}       = 33;
		$self->{errorString} = 'No GECOS specified';
		$self->warn;
		return undef;
	}

	#error if the user already exists
	my ( $name, $passwd, $uid, $gid, $quota, $comment, $gecos, $dir, $shell, $expire ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exists';
		$self->warn;
		return undef;
	}

	#connect to the LDAP server
	my $ldap = $self->connect();

	#search and get the first entry
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} eq '' ) {
		$self->{error} = 32;
		$self->{errorString}
			= 'Fetching the entry for the user failed under "'
			. $self->{ini}->{''}->{groupbase} . '"'
			. $mesg->{errorMessage} . '"';
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;

	#if $entry is not defined or does not exist under the specified base
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "'
			. $args{user}
			. '" does not exist in specified group base, "'
			. $self->{ini}->{''}->{userbase} . '", ';
		$self->warn;
		return undef;
	} ## end if ( !defined($entry) )

	$entry->delete( gecos => $gecos );
	$entry->add( gecos => $args{gecos} );

	#call a plugin if needed
	if ( defined( $self->{ini}->{''}->{pluginUserGECOSchange} ) ) {
		$self->plugin(
			{
				ldap  => $ldap,
				entry => $entry,
				do    => 'pluginUserGECOSchange',
			},
			\%args
		);
	} ## end if ( defined( $self->{ini}->{''}->{pluginUserGECOSchange...}))

	#update the entry
	my $mesg2 = $entry->update($ldap);
	if ( $mesg2->{errorMessage} ne '' ) {
		$self->{error} = 34;
		$self->{errorString}
			= 'Changing the GECOS to "'
			. $args{gecos}
			. '" from "'
			. $gecos
			. '" for  "'
			. $entry->dn
			. '" failed. $mesg2->{errorMessage}="'
			. $mesg2->{errorMessage} . '"';
		$self->warn;
		return undef;
	} ## end if ( $mesg2->{errorMessage} ne '' )

	#dump the entry if asked
	if ( $args{dump} ) {
		$entry->dump;
	}

	return 1;
} ## end sub userGECOSchange

=head2 userShellChange

This changes the shell for a user.

=head3 args hash

=head4 user

The user to act on.

=head4 shell

The shell to change this user to.

=head4 dump

Call the dump method on the group afterwards.

    $pt->userShellChange({
                          user=>'someUser',
                          shell=>'/bin/tcsh',
                          });

=cut

sub userShellChange {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	#error if we don't have a group name
	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	#error if no user has been specified
	if ( !defined( $args{shell} ) ) {
		$self->{error}       = 47;
		$self->{errorString} = 'No shell specified';
		$self->warn;
		return undef;
	}

	#error if the user already exists
	my ( $name, $passwd, $uid, $gid, $quota, $comment, $gecos, $dir, $shell, $expire ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exists';
		$self->warn;
		return undef;
	}

	#connect to the LDAP server
	my $ldap = $self->connect();

	#search and get the first entry
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error} = 32;
		$self->{errorString}
			= 'Fetching the entry for the user failed under "'
			. $self->{ini}->{''}->{groupbase} . '"'
			. $mesg->{errorMessage} . '"';
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;

	#if $entry is not defined or does not exist under the specified base
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "'
			. $args{user}
			. '" does not exist in specified group base, "'
			. $self->{ini}->{''}->{userbase} . '", ';
		$self->warn;
		return undef;
	} ## end if ( !defined($entry) )

	$entry->delete( loginShell => $shell );
	$entry->add( loginShell => $args{shell} );

	#call a plugin if needed
	if ( defined( $self->{ini}->{''}->{pluginUserShellChange} ) ) {
		$self->plugin(
			{
				ldap  => $ldap,
				entry => $entry,
				do    => 'pluginUserShellChange',
			},
			\%args
		);
	} ## end if ( defined( $self->{ini}->{''}->{pluginUserShellChange...}))

	#update the entry
	my $mesg2 = $entry->update($ldap);
	if ( $mesg2->{errorMessage} ne '' ) {
		$self->{error} = 34;
		$self->{errorString}
			= 'Changing the Shell to "'
			. $args{shell}
			. '" from "'
			. $shell
			. '" for  "'
			. $entry->dn
			. '" failed. $mesg2->{errorMessage}="'
			. $mesg2->{errorMessage} . '"';
		$self->warn;
		return undef;
	} ## end if ( $mesg2->{errorMessage} ne '' )

	#dump the entry if asked
	if ( $args{dump} ) {
		$entry->dump;
	}

	return 1;
} ## end sub userShellChange

=head2 userHomeChange

This changes the home directory for a user.

=head3 args hash

=head4 user

The user to act on.

=head4 home

What to change the home directory to.

=head4 dump

Call the dump method on the group afterwards.

    $pt->userShellChange({
                          user=>'someUser',
                          home=>'/home/foo',
                          });

=cut

sub userHomeChange {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	#error if no user has been specified
	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	#error if no home directory has been specified
	if ( !defined( $args{home} ) ) {
		$self->{error}       = 48;
		$self->{errorString} = 'No home directory specified';
		$self->warn;
		return undef;
	}

	#error if the user does not exist
	my ( $name, $passwd, $uid, $gid, $quota, $comment, $gecos, $dir, $shell, $expire ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exists';
		$self->warn;
		return undef;
	}

	#connect to the LDAP server
	my $ldap = $self->connect();

	#search and get the first entry
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error} = 32;
		$self->{errorString}
			= 'Fetching the entry for the user failed under "'
			. $self->{ini}->{''}->{userbase} . '"'
			. $mesg->{errorMessage} . '"';
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;

	#if $entry is not defined or does not exist under the specified base
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "'
			. $args{user}
			. '" does not exist in specified user base, "'
			. $self->{ini}->{''}->{userbase} . '", ';
		$self->warn;
		return undef;
	} ## end if ( !defined($entry) )

	$entry->delete( homeDirectory => $dir );
	$entry->add( homeDirectory => $args{home} );

	#call a plugin if needed
	if ( defined( $self->{ini}->{''}->{pluginUserHomeChange} ) ) {
		$self->plugin(
			{
				ldap  => $ldap,
				entry => $entry,
				do    => 'pluginUserHomeChange',
			},
			\%args
		);
	} ## end if ( defined( $self->{ini}->{''}->{pluginUserHomeChange...}))

	#update the entry
	my $mesg2 = $entry->update($ldap);
	if ( $mesg2->{errorMessage} ne '' ) {
		$self->{error} = 34;
		$self->{errorString}
			= 'Changing the home directory to "'
			. $args{home}
			. '" from "'
			. $dir
			. '" for "'
			. $entry->dn
			. '" failed. $mesg2->{errorMessage}="'
			. $mesg2->{errorMessage} . '"';
		$self->warn;
		return undef;
	} ## end if ( $mesg2->{errorMessage} ne '' )

	#dump the entry if asked
	if ( $args{dump} ) {
		$entry->dump;
	}

	return 1;
} ## end sub userHomeChange

=head2 userHasPassword

Returns true (1) if the user's LDAP entry has a C<userPassword> attribute set,
false (0) if it does not, or C<undef> on error.

=head3 args hash

=head4 user

The user to check.

    if ($pt->userHasPassword({ user => 'someUser' })) {
        print "password is set\n";
    }

=cut

sub userHasPassword {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	my ( $name, $passwd, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();

	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error} = 32;
		$self->{errorString}
			= 'Fetching the entry for the user under "'
			. $self->{ini}->{''}->{userbase} . '": '
			. $mesg->{errorMessage};
		$self->warn;
		return undef;
	}

	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	return defined( $entry->get_value('userPassword') ) ? 1 : 0;
} ## end sub userHasPassword

=head2 userSetPass

This changes the password for a user.

=head3 args hash

=head4 user

This is the user to act on.

=head4 pass

This is the new password to set.

    $pt->userSetPass({
                      user=>'someUser',
                      pass=>'whatever',
                      });

=cut

sub userSetPass {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	#error if we don't have a user name
	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	#error if we don't have a password
	if ( !defined( $args{pass} ) ) {
		$self->{error}       = 35;
		$self->{errorString} = 'No password specified.';
		$self->warn;
		return undef;
	}

	#error if the user already exists
	my ( $name, $passwd, $uid, $gid, $quota, $comment, $gcos, $dir, $shell, $expire ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exists';
		$self->warn;
		return undef;
	}

	#connect to the LDAP server
	my $ldap = $self->connect();

	#search and get the first entry
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error} = 32;
		$self->{errorString}
			= 'Fetching the entry for the user under "'
			. $self->{ini}->{''}->{userbase} . '"'
			. $mesg->{errorMessage} . '"';
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;

	#get the DN of the entry we will be changing
	my $dn = $entry->dn;

	my $mesg2 = $ldap->set_password( user => $dn, newpasswd => $args{pass} );
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error} = 36;
		$self->{errorString}
			= 'Fetching the entry for the user under "'
			. $self->{ini}->{''}->{userbase} . '"'
			. $mesg->{errorMessage} . '"';
		$self->warn;
		return undef;
	}

	#call a plugin if needed
	if ( defined( $self->{ini}->{''}->{pluginUserSetPass} ) ) {
		$self->plugin(
			{
				ldap  => $ldap,
				entry => $entry,
				do    => 'pluginUserSetPass',
			},
			\%args
		);
	} else {
		return 1;
	}

	#update the entry
	my $mesg3 = $entry->update($ldap);
	if ( $mesg3->{errorMessage} ne '' ) {
		$self->{error} = 34;
		$self->{errorString}
			= 'Calling the update method on the entry, "'
			. $entry->dn
			. '", failed. $mesg3->{errorMessage}="'
			. $mesg3->{errorMessage} . '"';
		$self->warn;
		return undef;
	} ## end if ( $mesg3->{errorMessage} ne '' )

	return 1;
} ## end sub userSetPass

=head2 userRemovePassword

Removes the C<userPassword> attribute from a user's LDAP entry entirely.
This is useful for disabling password-based authentication without deleting
the account.

=head3 args hash

=head4 user

The user to act on.

    $pt->userRemovePassword({ user => 'someUser' });

=cut

sub userRemovePassword {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	my ( $name, $passwd, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();

	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error} = 32;
		$self->{errorString}
			= 'Fetching the entry for the user under "'
			. $self->{ini}->{''}->{userbase} . '": '
			. $mesg->{errorMessage};
		$self->warn;
		return undef;
	}

	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	# Nothing to do if the attribute is not present
	return 1 unless defined $entry->get_value('userPassword');

	$entry->delete('userPassword');

	my $update = $entry->update($ldap);
	if ( $update->code ) {
		$self->{error}       = 34;
		$self->{errorString} = 'Removing userPassword from "' . $entry->dn . '" failed: ' . $update->error;
		$self->warn;
		return undef;
	}

	return 1;
} ## end sub userRemovePassword

=head2 userGIDchange

This changes the UID for a user.

=head3 args hash

=head4 user

The user to act on.

=head4 gid

The GID to change this user to. This GID must already exist.

=head4 dump

Call the dump method on the group afterwards.

    $pt->userGIDchange({
                        user=>'someUser',
                        gid=>'1234',
                        });

=cut

sub userGIDchange {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	#error if we don't have a group name
	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	#error if no user has been specified
	if ( !defined( $args{gid} ) ) {
		$self->{error}       = 28;
		$self->{errorString} = 'No GID specified';
		$self->warn;
		return undef;
	}

	#make sure the GID is complete numeric
	if ( !( $args{gid} =~ /^[0123456789]*$/ ) ) {
		$self->{error}       = 8;
		$self->{errorString} = 'The specified GID, "' . $args{gid} . '", is not numeric';
		$self->warn;
		return undef;
	}

	#error if the user already exists
	my ( $name, $passwd, $uid, $gid, $quota, $comment, $gcos, $dir, $shell, $expire ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exists';
		$self->warn;
		return undef;
	}

	#error if the user does not exists
	my ( $gname, $gpasswd, $ggid, $members ) = getgrgid( $args{gid} );
	if ( !defined($gname) ) {
		$self->{error}       = 14;
		$self->{errorString} = 'The group specified by GID "' . $args{gid} . '" does not exist';
		$self->warn;
		return undef;
	}

	#connect to the LDAP server
	my $ldap = $self->connect();

	#search and get the first entry
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error} = 32;
		$self->{errorString}
			= 'Fetching the entry for the user failed under "'
			. $self->{ini}->{''}->{userbase} . '"'
			. $mesg->{errorMessage} . '"';
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;

	#if $entry is not defined or does not exist under the specified base
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "'
			. $args{user}
			. '" does not exist in specified group base, "'
			. $self->{ini}->{''}->{userbase} . '", ';
		$self->warn;
		return undef;
	} ## end if ( !defined($entry) )

	$entry->delete( gidNumber => $gid );
	$entry->add( gidNumber => $args{gid} );

	#call a plugin if needed
	if ( defined( $self->{ini}->{''}->{pluginUserGIDchange} ) ) {
		$self->plugin(
			{
				ldap  => $ldap,
				entry => $entry,
				do    => 'pluginUserGIDchange',
			},
			\%args
		);
	} ## end if ( defined( $self->{ini}->{''}->{pluginUserGIDchange...}))

	#update the entry
	my $mesg2 = $entry->update($ldap);
	if ( $mesg2->{errorMessage} ne '' ) {
		$self->{error} = 29;
		$self->{errorString}
			= 'Changing the GID to "'
			. $args{gid}
			. '" from "'
			. $gid
			. '" for  "'
			. $entry->dn
			. '" failed. $mesg2->{errorMessage}="'
			. $mesg2->{errorMessage} . '"';
		$self->warn;
		return undef;
	} ## end if ( $mesg2->{errorMessage} ne '' )

	#dump the entry if asked
	if ( $args{dump} ) {
		$entry->dump;
	}

	return 1;
} ## end sub userGIDchange

=head2 userUIDchange

This changes the UID for a user.

=head3 args hash

=head4 user

The user to act on.

=head4 uid

The UID to change this user to.

=head4 dump

Call the dump method on the group afterwards.

    $pt->userUIDchange({
                        user=>'someUser',
                        uid=>'1234',
                        });

=cut

sub userUIDchange {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	#error if we don't have a group name
	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	#error if no user has been specified
	if ( !defined( $args{uid} ) ) {
		$self->{error}       = 30;
		$self->{errorString} = 'No UID specified';
		$self->warn;
		return undef;
	}

	#make sure the UID is complete numeric
	if ( !( $args{uid} =~ /^[0123456789]*$/ ) ) {
		$self->{error}       = 7;
		$self->{errorString} = 'The specified UID, "' . $args{uid} . '", is not numeric';
		$self->warn;
		return undef;
	}

	#error if the user already exists
	my ( $name, $passwd, $uid, $gid, $quota, $comment, $gcos, $dir, $shell, $expire ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exists';
		$self->warn;
		return undef;
	}

	#connect to the LDAP server
	my $ldap = $self->connect();

	#search and get the first entry
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error} = 32;
		$self->{errorString}
			= 'Fetching the entry for the user under "'
			. $self->{ini}->{''}->{userbase} . '"'
			. $mesg->{errorMessage} . '"';
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;

	#if $entry is not defined or does not exist under the specified base
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "'
			. $args{user}
			. '" does not exist in specified group base, "'
			. $self->{ini}->{''}->{userbase} . '", ';
		$self->warn;
		return undef;
	} ## end if ( !defined($entry) )

	$entry->delete( uidNumber => $uid );
	$entry->add( uidNumber => $args{uid} );

	#call a plugin if needed
	if ( defined( $self->{ini}->{''}->{pluginUserUIDchange} ) ) {
		$self->plugin(
			{
				ldap  => $ldap,
				entry => $entry,
				do    => 'pluginUserGIDchange',
			},
			\%args
		);
	} ## end if ( defined( $self->{ini}->{''}->{pluginUserUIDchange...}))

	#update the entry
	my $mesg2 = $entry->update($ldap);
	if ( $mesg2->{errorMessage} ne '' ) {
		$self->{error} = 31;
		$self->{errorString}
			= 'Changing the UID to "'
			. $args{uid}
			. '" from "'
			. $uid
			. '" for  "'
			. $entry->dn
			. '" failed. $mesg2->{errorMessage}="'
			. $mesg2->{errorMessage} . '"';
		$self->warn;
		return undef;
	} ## end if ( $mesg2->{errorMessage} ne '' )

	#dump the entry if asked
	if ( $args{dump} ) {
		$entry->dump;
	}

	return 1;
} ## end sub userUIDchange

=head1 ERROR CODES

=head2 1

Could not read config.

=head2 2

Missing required variable.

=head2 3

Can't find a free UID.

=head2 4

Can't find a free GID.

=head2 5

No user name specified.

=head2 6

No group name specified.

=head2 7

UID is not numeric.

=head2 8

GID is not numeric.

=head2 9

User already exists.

=head2 10

Group already exists.

=head2 11

Connecting to LDAP failed.

=head2 12

Net::LDAP::posixGroup failed.

=head2 13

Failed to bind to the LDAP server.

=head2 14

The group does not exist.

=head2 15

The group does not exist in LDAP or under specified group base.

=head2 16

Failed to delete the group's entry.

=head2 17

The user does not exist.

=head2 18

The user does not exist in LDAP or under specified user base.

=head2 19

Adding the new entry failed.

=head2 20

The GID already exists.

=head2 21

Failed to create home.

=head2 22

Copying the skeleton to the home location failed.

=head2 23

Failed to chown the new home directory.

=head2 24

Failed to chmod the new home directory.

=head2 25

Failed to update a entry when removing a memberUid.

=head2 26

Failed to remove the users home directory.

=head2 27

Faild to fetch a list posixGroup objects.

=head2 28

No GID specified.

=head2 29

Failed to update the entry when changing the GID.

=head2 30

No UID specified.

=head2 31

Failed to update the entry when changing the UID.

=head2 32

Failed to fetch the user entry.

=head2 33

No GECOS specified.

=head2 34

Failed to update the entry when changing the GECOS.

=head2 35

No password specified.

=head2 36

Updating the password for the user failed.

=head2 37

Errored when fetching a list of users that may possibly need updated.

=head2 38

No LDAP object given.

=head2 39

$opts{do} has not been specified.

=head2 40

The specified selection of plugins to run does not exist.

=head2 41

Exectuting a plugin failed.

=head2 42

$opts{entry} is not defined.

=head2 43

$opts{entry} is not a Net::LDAP::Entry object.

=head2 44

$opts{ldap} is not a Net::LDAP object.

=head2 45

$returned{error} is set to true.

=head2 46

Calling the LDAP update function on the entry modified by the userSetPass
plugin failed. The unix password has been set though.

=head2 47

No shell specified.

=head1 CONFIG FILE

The default is xdg_config_home().'/nisabarc', which wraps
around to "~/.config/nisabarc". The file format is ini.

The only required ones are 'bind', 'pass', 'groupbase', and
'userbase'.

    bind=cn=admin,dc=foo,dc=bar
    pass=somebl00dyp@ssw0rd
    userbase=ou=users,dc=foo,dc=bar
    groupbase=ou=groups,dc=foo,dc=bar

=head2 bind

This is the DN to bind as.

=head2 pass

This is the password for the bind DN.

=head2 userbase

This is the base for where the users are located.

=head2 groupbase

This is the base where the groups are located.

=head2 server

This is the LDAP server to connect to. If the server is not
specified, '127.0.0.1' is used.

=head2 port

This is the LDAP port to use. If the port is not specified, '389'
is used.

=head2 UIDstart

This is the first UID to start checking for existing users at. The default is '1001'.

=head2 GIDstart

This is the first GID to start checking for existing groups at. The default is '1001'.

=head2 defaultShell

This is the default shell for a user. The default is '/bin/tcsh'.

=head2 HOMEproto

The prototype for the home directory. %%USERNAME%% is replaced with
the username. The default is '/home/%%USERNAME%%/'.

=head2 skeletonHome

This is the location that will be copied for when creating a new home directory. If this is not defined,
a blanked one will be created. The default is '/etc/skel'.

=head2 chmodValue

This is the numeric value the newly created home directory will be chmoded to. The default is '640'.

=head2 chmodHome

If home should be chmoded. The default value is '1', true.

=head2 chownHome

If home should be chowned. The default value is '1', true.

=head2 createHome

If this is true, it the home directory for the user will be created. The default is '1'.

=head2 groupPrimary

This is the attribute to use for when creating the DN for the group entry. Either 'cn' or
'gidNumber' are currently accepted. The default is 'cn'.

=head2 userPrimary

This is the attribute to use for when creating the DN for the user entry. Either
'cn', 'uid', or 'uidNumber' are currently accepted. The default is 'uid'.

=head2 starttls

Wether or not it should try to do start_tls.

=head2 TLSverify

The verify mode for TLS. The default is 'none'.

=head3 none

The server may provide a certificate but it will not be
checked - this may mean you are be connected to the wrong
server.

=head3 optional

Verify only when the server offers a certificate.

=head3 require

The server must provide a certificate, and it must be valid.

=head2 SSLversion

This is the SSL versions accepted.

'sslv2', 'sslv3', 'sslv2/3', or 'tlsv1' are the possible values. The default
is 'tlsv1'.

=head2 SSLciphers

This is a list of ciphers to accept. The string is in the standard OpenSSL
format. The default value is 'ALL'.

=head2 removeGroup

This determines if it should try to remove the user's primary group after removing the
user.

The default value is '1', true.

=head2 removeHome

This determines if it should try to remove a user's home directory when deleting the
user.

The default value is '0', false.

=head2 userUpdate

This determines if it should update the primary GIDs for users after groupGIDchange
has been called.

The default value is '1', true.

=head2 pluginAddGroup

A comma seperated list of plugins to run when addGroup is called.

=head2 pluginAddUser

A comma seperated list of plugins to run when addUser is called.

=head2 pluginGroupAddUser

A comma seperated list of plugins to run when groupAddUser is called.

=head2 pluginGroupGIDchange

A comma seperated list of plugins to run when groupGIDchange is called.

=head2 pluginGroupRemoveUser

A comma seperated list of plugins to run when groupRemoveUser is called.

=head2 pluginUserGECOSchange

A comma seperated list of plugins to run when userGECOSchange is called.

=head2 pluginUserSetPass

A comma seperated list of plugins to run when userSetPass is called.

=head2 pluginUserGIDchange

A comma seperated list of plugins to run when userGIDchange is called.

=head2 pluginUserShellChange

A comma seperated list of plugins to run when userShellChange is called.

=head2 pluginUserUIDchange

A comma seperated list of plugins to run when userUIDchange is called.

=head2 pluginDeleteUser

A comma seperated list of plugins to run when deleteUser is called.

=head2 pluginDeleteGroup

A comma seperated list of plugins to run when deleteGroup is called.

=head1 PLUGINS

Plugins are supported by the functions specified in the config section.

A plugin may be specified for any of those by setting that value to a comma seperated
list of plugins. For example if you wanted to call 'App::Nisaba::Plugins::Dump' and then
'Foo::Bar' for a userSetPass, you would set the value 'pluginsUserSetPass' equal to
'App::Nisaba::Plugins::Dump,Foo::Bar'.

Both hashes specified in the section covering the plugin function. The key 'self' is added
to %opts before it is passed to the plugin. That key contains a copy of the App::Nisaba object.

A plugin is a Perl module that is used via eval and then the function 'plugin' is called on
it. The expected return is

The plugin is called before the update method is called on a Net::LDAP::Entry object, except for
the function 'userSetPass'. It is called after the password is updated.

=head2 example

What is shown below is copied from App::Nisaba::Plugins::Dump. This is a simple plugin
that calls Data::Dumper->Dumper on what is passed to it.

    package App::Nisaba::Plugins::Dump;
    use warnings;
    use strict;
    use Data::Dumper;
    our $VERSION = '0.0.0';
    sub plugin{
        my %opts;
        if(defined($_[1])){
            %opts= %{$_[1]};
        };
        my %args;
        if(defined($_[2])){
                %args= %{$_[2]};
        };
        print '%opts=...'."\n".Dumper(\%opts)."\n\n".'%args=...'."\n".Dumper(\%args);
        my %returned;
        $returned{error}=undef;
        return %returned;
    }

=head2 ensureInetOrgPerson

Ensures that a L<Net::LDAP::Entry> has C<inetOrgPerson> (and its required
ancestor objectClasses C<person> and C<organizationalPerson>) present in its
C<objectClass> attribute.  If any are missing they are added to the in-memory
entry.  If C<person> is being added and the entry has no C<sn> value, C<sn>
is set to C<$user> as a fallback, since C<sn> is a mandatory attribute of the
C<person> schema.

The entry is B<not> written back to LDAP by this method - call
C<< $entry->update($ldap) >> afterwards as usual.

=head3 args

=head4 entry

A L<Net::LDAP::Entry> object for the user, as returned by an LDAP search.

=head4 user

The uid string for the user.  Used as the fallback C<sn> value if one needs
to be added.

    my $entry = $mesg->pop_entry;
    $pt->ensureInetOrgPerson( $entry, 'jsmith' );
    $entry->add( title => 'Engineer' );
    $entry->update($ldap);

=cut

sub ensureInetOrgPerson {
	my ( $self, $entry, $user ) = @_;
	my @oc     = $entry->get_value('objectClass');
	my %oc_map = map { lc($_) => 1 } @oc;
	my @to_add;
	push @to_add, 'person'               unless $oc_map{person};
	push @to_add, 'organizationalPerson' unless $oc_map{organizationalperson};
	push @to_add, 'inetOrgPerson'        unless $oc_map{inetorgperson};
	if (@to_add) {
		$entry->add( objectClass => \@to_add );
		unless ( $entry->get_value('sn') ) {
			$entry->add( sn => $user );
		}
	}
} ## end sub ensureInetOrgPerson

=head2 userTitleChange

Change the title (job title) for a user.

=head3 args hash

=head4 user

The user to act on.

=head4 title

The new title value.

=head4 dump

Call the dump method on the entry afterwards.

    $pt->userTitleChange({ user => 'someUser', title => 'Senior Engineer' });

=cut

sub userTitleChange {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{title} ) ) {
		$self->{error}       = 52;
		$self->{errorString} = 'No title specified';
		$self->warn;
		return undef;
	}

	my ( $name, $passwd, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	$self->ensureInetOrgPerson( $entry, $args{user} );
	my $old = $entry->get_value('title');
	$entry->delete( title => [$old] ) if defined $old;
	$entry->add( title => $args{title} );

	my $mesg2 = $entry->update($ldap);
	if ( $mesg2->{errorMessage} ne '' ) {
		$self->{error} = 34;
		$self->{errorString}
			= 'Changing title to "' . $args{title} . '" for "' . $entry->dn . '" failed: ' . $mesg2->{errorMessage};
		$self->warn;
		return undef;
	}

	$entry->dump if $args{dump};
	return 1;
} ## end sub userTitleChange

=head2 userRoomNumberChange

Change the roomNumber for a user.

=head3 args hash

=head4 user

The user to act on.

=head4 roomNumber

The new room number value.

=head4 dump

Call the dump method on the entry afterwards.

    $pt->userRoomNumberChange({ user => 'someUser', roomNumber => '4B-12' });

=cut

sub userRoomNumberChange {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{roomNumber} ) ) {
		$self->{error}       = 53;
		$self->{errorString} = 'No roomNumber specified';
		$self->warn;
		return undef;
	}

	my ( $name, $passwd, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	$self->ensureInetOrgPerson( $entry, $args{user} );
	my $old = $entry->get_value('roomNumber');
	$entry->delete( roomNumber => [$old] ) if defined $old;
	$entry->add( roomNumber => $args{roomNumber} );

	my $mesg2 = $entry->update($ldap);
	if ( $mesg2->{errorMessage} ne '' ) {
		$self->{error} = 34;
		$self->{errorString}
			= 'Changing roomNumber to "'
			. $args{roomNumber}
			. '" for "'
			. $entry->dn
			. '" failed: '
			. $mesg2->{errorMessage};
		$self->warn;
		return undef;
	} ## end if ( $mesg2->{errorMessage} ne '' )

	$entry->dump if $args{dump};
	return 1;
} ## end sub userRoomNumberChange

=head2 userEmployeeNumberChange

Change the employeeNumber for a user.

=head3 args hash

=head4 user

The user to act on.

=head4 employeeNumber

The new employee number value.

=head4 dump

Call the dump method on the entry afterwards.

    $pt->userEmployeeNumberChange({ user => 'someUser', employeeNumber => 'E-1042' });

=cut

sub userEmployeeNumberChange {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{employeeNumber} ) ) {
		$self->{error}       = 54;
		$self->{errorString} = 'No employeeNumber specified';
		$self->warn;
		return undef;
	}

	my ( $name, $passwd, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	$self->ensureInetOrgPerson( $entry, $args{user} );
	my $old = $entry->get_value('employeeNumber');
	$entry->delete( employeeNumber => [$old] ) if defined $old;
	$entry->add( employeeNumber => $args{employeeNumber} );

	my $mesg2 = $entry->update($ldap);
	if ( $mesg2->{errorMessage} ne '' ) {
		$self->{error} = 34;
		$self->{errorString}
			= 'Changing employeeNumber to "'
			. $args{employeeNumber}
			. '" for "'
			. $entry->dn
			. '" failed: '
			. $mesg2->{errorMessage};
		$self->warn;
		return undef;
	} ## end if ( $mesg2->{errorMessage} ne '' )

	$entry->dump if $args{dump};
	return 1;
} ## end sub userEmployeeNumberChange

=head2 userEmployeeTypeChange

Change the employeeType for a user.

=head3 args hash

=head4 user

The user to act on.

=head4 employeeType

The new employee type value (e.g. 'staff', 'contractor').

=head4 dump

Call the dump method on the entry afterwards.

    $pt->userEmployeeTypeChange({ user => 'someUser', employeeType => 'contractor' });

=cut

sub userEmployeeTypeChange {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{employeeType} ) ) {
		$self->{error}       = 55;
		$self->{errorString} = 'No employeeType specified';
		$self->warn;
		return undef;
	}

	my ( $name, $passwd, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	$self->ensureInetOrgPerson( $entry, $args{user} );
	my $old = $entry->get_value('employeeType');
	$entry->delete( employeeType => [$old] ) if defined $old;
	$entry->add( employeeType => $args{employeeType} );

	my $mesg2 = $entry->update($ldap);
	if ( $mesg2->{errorMessage} ne '' ) {
		$self->{error} = 34;
		$self->{errorString}
			= 'Changing employeeType to "'
			. $args{employeeType}
			. '" for "'
			. $entry->dn
			. '" failed: '
			. $mesg2->{errorMessage};
		$self->warn;
		return undef;
	} ## end if ( $mesg2->{errorMessage} ne '' )

	$entry->dump if $args{dump};
	return 1;
} ## end sub userEmployeeTypeChange

=head2 userMailAdd

Add an email address to a user. Multiple values are supported.

=head3 args hash

=head4 user

The user to act on.

=head4 mail

The email address to add.

=head4 dump

Call the dump method on the entry afterwards.

    $pt->userMailAdd({ user => 'someUser', mail => 'user@example.com' });

=cut

sub userMailAdd {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{mail} ) ) {
		$self->{error}       = 49;
		$self->{errorString} = 'No mail address specified';
		$self->warn;
		return undef;
	}

	my ( $name, $passwd, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	$self->ensureInetOrgPerson( $entry, $args{user} );
	$entry->add( mail => $args{mail} );

	my $mesg2 = $entry->update($ldap);
	if ( $mesg2->{errorMessage} ne '' ) {
		$self->{error} = 34;
		$self->{errorString}
			= 'Adding mail "' . $args{mail} . '" for "' . $entry->dn . '" failed: ' . $mesg2->{errorMessage};
		$self->warn;
		return undef;
	}

	$entry->dump if $args{dump};
	return 1;
} ## end sub userMailAdd

=head2 userMailRemove

Remove an email address from a user.

=head3 args hash

=head4 user

The user to act on.

=head4 mail

The email address to remove.

=head4 dump

Call the dump method on the entry afterwards.

    $pt->userMailRemove({ user => 'someUser', mail => 'user@example.com' });

=cut

sub userMailRemove {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{mail} ) ) {
		$self->{error}       = 49;
		$self->{errorString} = 'No mail address specified';
		$self->warn;
		return undef;
	}

	my ( $name, $passwd, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	$entry->delete( mail => [ $args{mail} ] );

	my $mesg2 = $entry->update($ldap);
	if ( $mesg2->{errorMessage} ne '' ) {
		$self->{error} = 34;
		$self->{errorString}
			= 'Removing mail "' . $args{mail} . '" for "' . $entry->dn . '" failed: ' . $mesg2->{errorMessage};
		$self->warn;
		return undef;
	}

	$entry->dump if $args{dump};
	return 1;
} ## end sub userMailRemove

=head2 userTelephoneNumberAdd

Add a telephone number to a user. Multiple values are supported.

=head3 args hash

=head4 user

The user to act on.

=head4 telephoneNumber

The telephone number to add.

=head4 dump

Call the dump method on the entry afterwards.

    $pt->userTelephoneNumberAdd({ user => 'someUser', telephoneNumber => '+1 555 000 1234' });

=cut

sub userTelephoneNumberAdd {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{telephoneNumber} ) ) {
		$self->{error}       = 50;
		$self->{errorString} = 'No telephoneNumber specified';
		$self->warn;
		return undef;
	}

	my ( $name, $passwd, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	$self->ensureInetOrgPerson( $entry, $args{user} );
	$entry->add( telephoneNumber => $args{telephoneNumber} );

	my $mesg2 = $entry->update($ldap);
	if ( $mesg2->{errorMessage} ne '' ) {
		$self->{error} = 34;
		$self->{errorString}
			= 'Adding telephoneNumber "'
			. $args{telephoneNumber}
			. '" for "'
			. $entry->dn
			. '" failed: '
			. $mesg2->{errorMessage};
		$self->warn;
		return undef;
	} ## end if ( $mesg2->{errorMessage} ne '' )

	$entry->dump if $args{dump};
	return 1;
} ## end sub userTelephoneNumberAdd

=head2 userTelephoneNumberRemove

Remove a telephone number from a user.

=head3 args hash

=head4 user

The user to act on.

=head4 telephoneNumber

The telephone number to remove.

=head4 dump

Call the dump method on the entry afterwards.

    $pt->userTelephoneNumberRemove({ user => 'someUser', telephoneNumber => '+1 555 000 1234' });

=cut

sub userTelephoneNumberRemove {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{telephoneNumber} ) ) {
		$self->{error}       = 50;
		$self->{errorString} = 'No telephoneNumber specified';
		$self->warn;
		return undef;
	}

	my ( $name, $passwd, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	$entry->delete( telephoneNumber => [ $args{telephoneNumber} ] );

	my $mesg2 = $entry->update($ldap);
	if ( $mesg2->{errorMessage} ne '' ) {
		$self->{error} = 34;
		$self->{errorString}
			= 'Removing telephoneNumber "'
			. $args{telephoneNumber}
			. '" for "'
			. $entry->dn
			. '" failed: '
			. $mesg2->{errorMessage};
		$self->warn;
		return undef;
	} ## end if ( $mesg2->{errorMessage} ne '' )

	$entry->dump if $args{dump};
	return 1;
} ## end sub userTelephoneNumberRemove

=head2 userMobileAdd

Add a mobile number to a user. Multiple values are supported.

=head3 args hash

=head4 user

The user to act on.

=head4 mobile

The mobile number to add.

=head4 dump

Call the dump method on the entry afterwards.

    $pt->userMobileAdd({ user => 'someUser', mobile => '+1 555 000 5678' });

=cut

sub userMobileAdd {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{mobile} ) ) {
		$self->{error}       = 51;
		$self->{errorString} = 'No mobile number specified';
		$self->warn;
		return undef;
	}

	my ( $name, $passwd, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	$self->ensureInetOrgPerson( $entry, $args{user} );
	$entry->add( mobile => $args{mobile} );

	my $mesg2 = $entry->update($ldap);
	if ( $mesg2->{errorMessage} ne '' ) {
		$self->{error} = 34;
		$self->{errorString}
			= 'Adding mobile "' . $args{mobile} . '" for "' . $entry->dn . '" failed: ' . $mesg2->{errorMessage};
		$self->warn;
		return undef;
	}

	$entry->dump if $args{dump};
	return 1;
} ## end sub userMobileAdd

=head2 userMobileRemove

Remove a mobile number from a user.

=head3 args hash

=head4 user

The user to act on.

=head4 mobile

The mobile number to remove.

=head4 dump

Call the dump method on the entry afterwards.

    $pt->userMobileRemove({ user => 'someUser', mobile => '+1 555 000 5678' });

=cut

sub userMobileRemove {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{mobile} ) ) {
		$self->{error}       = 51;
		$self->{errorString} = 'No mobile number specified';
		$self->warn;
		return undef;
	}

	my ( $name, $passwd, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	$entry->delete( mobile => [ $args{mobile} ] );

	my $mesg2 = $entry->update($ldap);
	if ( $mesg2->{errorMessage} ne '' ) {
		$self->{error} = 34;
		$self->{errorString}
			= 'Removing mobile "' . $args{mobile} . '" for "' . $entry->dn . '" failed: ' . $mesg2->{errorMessage};
		$self->warn;
		return undef;
	}

	$entry->dump if $args{dump};
	return 1;
} ## end sub userMobileRemove

=head2 userPreferredLanguageAdd

Add a preferred language to a user. Multiple values are supported.

=head3 args hash

=head4 user

The user to act on.

=head4 preferredLanguage

The language tag to add (e.g. 'en', 'fr', 'de').

=head4 dump

Call the dump method on the entry afterwards.

    $pt->userPreferredLanguageAdd({ user => 'someUser', preferredLanguage => 'en' });

=cut

sub userPreferredLanguageAdd {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{preferredLanguage} ) ) {
		$self->{error}       = 56;
		$self->{errorString} = 'No preferredLanguage specified';
		$self->warn;
		return undef;
	}

	my ( $name, $passwd, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	$self->ensureInetOrgPerson( $entry, $args{user} );
	$entry->add( preferredLanguage => $args{preferredLanguage} );

	my $mesg2 = $entry->update($ldap);
	if ( $mesg2->{errorMessage} ne '' ) {
		$self->{error} = 34;
		$self->{errorString}
			= 'Adding preferredLanguage "'
			. $args{preferredLanguage}
			. '" for "'
			. $entry->dn
			. '" failed: '
			. $mesg2->{errorMessage};
		$self->warn;
		return undef;
	} ## end if ( $mesg2->{errorMessage} ne '' )

	$entry->dump if $args{dump};
	return 1;
} ## end sub userPreferredLanguageAdd

=head2 userPreferredLanguageRemove

Remove a preferred language from a user.

=head3 args hash

=head4 user

The user to act on.

=head4 preferredLanguage

The language tag to remove.

=head4 dump

Call the dump method on the entry afterwards.

    $pt->userPreferredLanguageRemove({ user => 'someUser', preferredLanguage => 'en' });

=cut

sub userPreferredLanguageRemove {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{preferredLanguage} ) ) {
		$self->{error}       = 56;
		$self->{errorString} = 'No preferredLanguage specified';
		$self->warn;
		return undef;
	}

	my ( $name, $passwd, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	$entry->delete( preferredLanguage => [ $args{preferredLanguage} ] );

	my $mesg2 = $entry->update($ldap);
	if ( $mesg2->{errorMessage} ne '' ) {
		$self->{error} = 34;
		$self->{errorString}
			= 'Removing preferredLanguage "'
			. $args{preferredLanguage}
			. '" for "'
			. $entry->dn
			. '" failed: '
			. $mesg2->{errorMessage};
		$self->warn;
		return undef;
	} ## end if ( $mesg2->{errorMessage} ne '' )

	$entry->dump if $args{dump};
	return 1;
} ## end sub userPreferredLanguageRemove

=head2 userLabeledURIAdd

Add a labeled URI to a user. Multiple values are supported.

=head3 args hash

=head4 user

The user to act on.

=head4 labeledURI

The URI to add (optionally with a label, e.g. 'https://example.com My Page').

=head4 dump

Call the dump method on the entry afterwards.

    $pt->userLabeledURIAdd({ user => 'someUser', labeledURI => 'https://example.com My Page' });

=cut

sub userLabeledURIAdd {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{labeledURI} ) ) {
		$self->{error}       = 57;
		$self->{errorString} = 'No labeledURI specified';
		$self->warn;
		return undef;
	}

	my ( $name, $passwd, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	$self->ensureInetOrgPerson( $entry, $args{user} );
	$entry->add( labeledURI => $args{labeledURI} );

	my $mesg2 = $entry->update($ldap);
	if ( $mesg2->{errorMessage} ne '' ) {
		$self->{error} = 34;
		$self->{errorString}
			= 'Adding labeledURI "'
			. $args{labeledURI}
			. '" for "'
			. $entry->dn
			. '" failed: '
			. $mesg2->{errorMessage};
		$self->warn;
		return undef;
	} ## end if ( $mesg2->{errorMessage} ne '' )

	$entry->dump if $args{dump};
	return 1;
} ## end sub userLabeledURIAdd

=head2 userLabeledURIRemove

Remove a labeled URI from a user.

=head3 args hash

=head4 user

The user to act on.

=head4 labeledURI

The URI value to remove (must match exactly as stored).

=head4 dump

Call the dump method on the entry afterwards.

    $pt->userLabeledURIRemove({ user => 'someUser', labeledURI => 'https://example.com My Page' });

=cut

sub userLabeledURIRemove {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{labeledURI} ) ) {
		$self->{error}       = 57;
		$self->{errorString} = 'No labeledURI specified';
		$self->warn;
		return undef;
	}

	my ( $name, $passwd, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	$entry->delete( labeledURI => [ $args{labeledURI} ] );

	my $mesg2 = $entry->update($ldap);
	if ( $mesg2->{errorMessage} ne '' ) {
		$self->{error} = 34;
		$self->{errorString}
			= 'Removing labeledURI "'
			. $args{labeledURI}
			. '" for "'
			. $entry->dn
			. '" failed: '
			. $mesg2->{errorMessage};
		$self->warn;
		return undef;
	} ## end if ( $mesg2->{errorMessage} ne '' )

	$entry->dump if $args{dump};
	return 1;
} ## end sub userLabeledURIRemove

=head2 userSNchange

Change the surname (C<sn>) for a user.

=head3 args hash

=head4 user

The user to act on.

=head4 sn

The new surname value.

=head4 dump

Call the dump method on the entry afterwards.

    $pt->userSNchange({ user => 'jsmith', sn => 'Smith' });

=cut

sub userSNchange {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{sn} ) ) {
		$self->{error}       = 58;
		$self->{errorString} = 'No sn specified';
		$self->warn;
		return undef;
	}

	my ( $name, $passwd, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	$self->ensureInetOrgPerson( $entry, $args{user} );
	my $old = $entry->get_value('sn');
	$entry->delete( sn => [$old] ) if defined $old;
	$entry->add( sn => $args{sn} );

	my $mesg2 = $entry->update($ldap);
	if ( $mesg2->{errorMessage} ne '' ) {
		$self->{error} = 34;
		$self->{errorString}
			= 'Changing sn to "' . $args{sn} . '" for "' . $entry->dn . '" failed: ' . $mesg2->{errorMessage};
		$self->warn;
		return undef;
	}

	$entry->dump if $args{dump};
	return 1;
} ## end sub userSNchange

=head2 userGivenNameChange

Change the given name (C<givenName>) for a user.

=head3 args hash

=head4 user

The user to act on.

=head4 givenName

The new given name value.

=head4 dump

Call the dump method on the entry afterwards.

    $pt->userGivenNameChange({ user => 'jsmith', givenName => 'John' });

=cut

sub userGivenNameChange {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{givenName} ) ) {
		$self->{error}       = 59;
		$self->{errorString} = 'No givenName specified';
		$self->warn;
		return undef;
	}

	my ( $name, $passwd, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	$self->ensureInetOrgPerson( $entry, $args{user} );
	my $old = $entry->get_value('givenName');
	$entry->delete( givenName => [$old] ) if defined $old;
	$entry->add( givenName => $args{givenName} );

	my $mesg2 = $entry->update($ldap);
	if ( $mesg2->{errorMessage} ne '' ) {
		$self->{error} = 34;
		$self->{errorString}
			= 'Changing givenName to "'
			. $args{givenName}
			. '" for "'
			. $entry->dn
			. '" failed: '
			. $mesg2->{errorMessage};
		$self->warn;
		return undef;
	} ## end if ( $mesg2->{errorMessage} ne '' )

	$entry->dump if $args{dump};
	return 1;
} ## end sub userGivenNameChange

=head2 userDisplayNameChange

Change the display name (C<displayName>) for a user.

=head3 args hash

=head4 user

The user to act on.

=head4 displayName

The new display name value.

=head4 dump

Call the dump method on the entry afterwards.

    $pt->userDisplayNameChange({ user => 'jsmith', displayName => 'John Smith' });

=cut

sub userDisplayNameChange {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{displayName} ) ) {
		$self->{error}       = 63;
		$self->{errorString} = 'No displayName specified';
		$self->warn;
		return undef;
	}

	my ( $name, $passwd, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	$self->ensureInetOrgPerson( $entry, $args{user} );
	my $old = $entry->get_value('displayName');
	$entry->delete( displayName => [$old] ) if defined $old;
	$entry->add( displayName => $args{displayName} );

	my $mesg2 = $entry->update($ldap);
	if ( $mesg2->{errorMessage} ne '' ) {
		$self->{error} = 34;
		$self->{errorString}
			= 'Changing displayName to "'
			. $args{displayName}
			. '" for "'
			. $entry->dn
			. '" failed: '
			. $mesg2->{errorMessage};
		$self->warn;
		return undef;
	} ## end if ( $mesg2->{errorMessage} ne '' )

	$entry->dump if $args{dump};
	return 1;
} ## end sub userDisplayNameChange

=head2 userHomePostalAddressChange

Change the home postal address (C<homePostalAddress>) for a user.

=head3 args hash

=head4 user

The user to act on.

=head4 homePostalAddress

The new home postal address value.

=head4 dump

Call the dump method on the entry afterwards.

    $pt->userHomePostalAddressChange({ user => 'jsmith', homePostalAddress => '123 Main St$Springfield$IL 62701$USA' });

=cut

sub userHomePostalAddressChange {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{homePostalAddress} ) ) {
		$self->{error}       = 62;
		$self->{errorString} = 'No homePostalAddress specified';
		$self->warn;
		return undef;
	}

	my ( $name, $passwd, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	$self->ensureInetOrgPerson( $entry, $args{user} );
	my $old = $entry->get_value('homePostalAddress');
	$entry->delete( homePostalAddress => [$old] ) if defined $old;
	$entry->add( homePostalAddress => $args{homePostalAddress} );

	my $mesg2 = $entry->update($ldap);
	if ( $mesg2->{errorMessage} ne '' ) {
		$self->{error}       = 34;
		$self->{errorString} = 'Changing homePostalAddress for "' . $entry->dn . '" failed: ' . $mesg2->{errorMessage};
		$self->warn;
		return undef;
	}

	$entry->dump if $args{dump};
	return 1;
} ## end sub userHomePostalAddressChange

=head2 userDescriptionAdd

Add a description value to a user. Multiple values are supported.

=head3 args hash

=head4 user

The user to act on.

=head4 description

The description string to add.

=head4 dump

Call the dump method on the entry afterwards.

    $pt->userDescriptionAdd({ user => 'jsmith', description => 'Linux sysadmin' });

=cut

sub userDescriptionAdd {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{description} ) ) {
		$self->{error}       = 60;
		$self->{errorString} = 'No description specified';
		$self->warn;
		return undef;
	}

	my ( $name, $passwd, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	$self->ensureInetOrgPerson( $entry, $args{user} );
	$entry->add( description => $args{description} );

	my $mesg2 = $entry->update($ldap);
	if ( $mesg2->{errorMessage} ne '' ) {
		$self->{error}       = 34;
		$self->{errorString} = 'Adding description for "' . $entry->dn . '" failed: ' . $mesg2->{errorMessage};
		$self->warn;
		return undef;
	}

	$entry->dump if $args{dump};
	return 1;
} ## end sub userDescriptionAdd

=head2 userDescriptionRemove

Remove a description value from a user.

=head3 args hash

=head4 user

The user to act on.

=head4 description

The description string to remove (must match exactly as stored).

=head4 dump

Call the dump method on the entry afterwards.

    $pt->userDescriptionRemove({ user => 'jsmith', description => 'Linux sysadmin' });

=cut

sub userDescriptionRemove {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{description} ) ) {
		$self->{error}       = 60;
		$self->{errorString} = 'No description specified';
		$self->warn;
		return undef;
	}

	my ( $name, $passwd, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	$entry->delete( description => [ $args{description} ] );

	my $mesg2 = $entry->update($ldap);
	if ( $mesg2->{errorMessage} ne '' ) {
		$self->{error}       = 34;
		$self->{errorString} = 'Removing description for "' . $entry->dn . '" failed: ' . $mesg2->{errorMessage};
		$self->warn;
		return undef;
	}

	$entry->dump if $args{dump};
	return 1;
} ## end sub userDescriptionRemove

=head2 userPostalAddressAdd

Add a postal address (C<postalAddress>) to a user. Multiple values are supported.

=head3 args hash

=head4 user

The user to act on.

=head4 postalAddress

The postal address string to add.  Use C<$> as the line separator per RFC 4517
(e.g. C<123 Main St$Springfield$IL 62701$USA>).

=head4 dump

Call the dump method on the entry afterwards.

    $pt->userPostalAddressAdd({ user => 'jsmith', postalAddress => '123 Main St$Springfield$IL 62701$USA' });

=cut

sub userPostalAddressAdd {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{postalAddress} ) ) {
		$self->{error}       = 61;
		$self->{errorString} = 'No postalAddress specified';
		$self->warn;
		return undef;
	}

	my ( $name, $passwd, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	$self->ensureInetOrgPerson( $entry, $args{user} );
	$entry->add( postalAddress => $args{postalAddress} );

	my $mesg2 = $entry->update($ldap);
	if ( $mesg2->{errorMessage} ne '' ) {
		$self->{error}       = 34;
		$self->{errorString} = 'Adding postalAddress for "' . $entry->dn . '" failed: ' . $mesg2->{errorMessage};
		$self->warn;
		return undef;
	}

	$entry->dump if $args{dump};
	return 1;
} ## end sub userPostalAddressAdd

=head2 userPostalAddressRemove

Remove a postal address from a user.

=head3 args hash

=head4 user

The user to act on.

=head4 postalAddress

The postal address string to remove (must match exactly as stored).

=head4 dump

Call the dump method on the entry afterwards.

    $pt->userPostalAddressRemove({ user => 'jsmith', postalAddress => '123 Main St$Springfield$IL 62701$USA' });

=cut

sub userPostalAddressRemove {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{postalAddress} ) ) {
		$self->{error}       = 61;
		$self->{errorString} = 'No postalAddress specified';
		$self->warn;
		return undef;
	}

	my ( $name, $passwd, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	$entry->delete( postalAddress => [ $args{postalAddress} ] );

	my $mesg2 = $entry->update($ldap);
	if ( $mesg2->{errorMessage} ne '' ) {
		$self->{error}       = 34;
		$self->{errorString} = 'Removing postalAddress for "' . $entry->dn . '" failed: ' . $mesg2->{errorMessage};
		$self->warn;
		return undef;
	}

	$entry->dump if $args{dump};
	return 1;
} ## end sub userPostalAddressRemove

=head2 userConvertToInetOrgPerson

Converts a user's LDAP entry to use the C<inetOrgPerson> objectClass,
enabling contact and profile attributes.

Because OpenLDAP does not permit changing the structural objectClass chain of
an existing entry (C<account> and C<person>/C<inetOrgPerson> are independent
structural chains), this method performs a B<delete-and-re-add>: the original
entry is deleted and immediately re-added with the corrected objectClass list.

Specifically it:

=over 4

=item * Removes C<account> from the objectClass list.

=item * Adds C<person>, C<organizationalPerson>, and C<inetOrgPerson>.

=item * Ensures C<sn> is populated (required by C<person>), falling back to
the uid if unset.

=back

If the delete succeeds but the re-add fails, a full diagnostic dump is printed
to STDERR and an error is set.  The original entry will need to be restored
manually or from a backup.

Returns 1 on success.  If the entry already has C<inetOrgPerson> the method
returns 1 immediately without touching the entry.

=head3 args hash

=head4 user

The user to convert.

=head4 dump

Call the dump method on the resulting entry afterwards.

    $pt->userConvertToInetOrgPerson({ user => 'jsmith' });

=cut

sub userConvertToInetOrgPerson {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	my ( $name, $passwd, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ') (uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	# Already converted — nothing to do
	my %oc_map = map { lc($_) => 1 } $entry->get_value('objectClass');
	return 1 if $oc_map{inetorgperson};

	# Snapshot original for diagnostics
	my $before = _entryToString($entry);

	# Build the new objectClass list: drop account, add inetOrgPerson chain
	my @new_oc     = grep { lc($_) ne 'account' } $entry->get_value('objectClass');
	my %new_oc_map = map  { lc($_) => 1 } @new_oc;
	my @oc_added;
	for my $oc (qw(top person organizationalPerson inetOrgPerson)) {
		unless ( $new_oc_map{ lc($oc) } ) {
			push @new_oc,   $oc;
			push @oc_added, $oc;
		}
	}
	my $sn_to_add = $entry->get_value('sn') ? undef : $args{user};

	# Build change description for diagnostics
	my $changes = $oc_map{account} ? "  Remove objectClass: account\n" : '';
	$changes .= "  Add objectClass: $_\n" for @oc_added;
	$changes .= "  Add sn: $sn_to_add (fallback — not already set)\n" if defined $sn_to_add;

	# Construct the replacement entry with the same DN and all attributes
	my $new_entry = Net::LDAP::Entry->new;
	$new_entry->dn( $entry->dn );
	for my $attr ( $entry->attributes ) {
		next if lc($attr) eq 'objectclass';
		$new_entry->add( $attr => [ $entry->get_value($attr) ] );
	}
	$new_entry->add( objectClass => \@new_oc );
	$new_entry->add( sn          => $sn_to_add ) if defined $sn_to_add;

	my $after = _entryToString($new_entry);

	# Delete the original entry
	my $del_mesg = $ldap->delete( $entry->dn );
	if ( $del_mesg->code ) {
		$self->{error}       = 34;
		$self->{errorString} = 'Deleting "' . $entry->dn . '" prior to re-add failed: ' . $del_mesg->error;
		warn "userConvertToInetOrgPerson diagnostic dump\n"
			. "=== Original entry ===\n"
			. $before
			. "=== Attempted changes ===\n"
			. $changes
			. "=== Resulting entry (not written) ===\n"
			. $after;
		$self->warn;
		return undef;
	} ## end if ( $del_mesg->code )

	# Re-add with the corrected objectClass chain
	my $add_mesg = $ldap->add($new_entry);
	if ( $add_mesg->code ) {
		$self->{error} = 34;
		$self->{errorString}
			= 'Re-adding "'
			. $entry->dn
			. '" as inetOrgPerson failed: '
			. $add_mesg->error
			. ' — original entry was deleted and must be restored manually';
		warn "userConvertToInetOrgPerson diagnostic dump\n"
			. "=== Original entry (now deleted) ===\n"
			. $before
			. "=== Attempted changes ===\n"
			. $changes
			. "=== Resulting entry (failed to write) ===\n"
			. $after;
		$self->warn;
		return undef;
	} ## end if ( $add_mesg->code )

	$new_entry->dump if $args{dump};
	return 1;
} ## end sub userConvertToInetOrgPerson

=head2 userCNadd

Add an additional C<cn> value to a user entry.

=head3 args hash

=head4 user

The username (uid) to act on. Required.

=head4 cn

The CN value to add. Required.

=head4 dump

Call the dump method on the entry afterwards.

    $pt->userCNadd({ user => 'jsmith', cn => 'John Smith' });

=cut

sub userCNadd {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{cn} ) || $args{cn} eq '' ) {
		$self->{error}       = 70;
		$self->{errorString} = 'No CN value specified';
		$self->warn;
		return undef;
	}

	my ( $name, $passwd, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ')(uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	$entry->add( cn => $args{cn} );

	my $update = $entry->update($ldap);
	if ( $update->{errorMessage} ne '' ) {
		$self->{error} = 34;
		$self->{errorString}
			= 'Adding cn "' . $args{cn} . '" for "' . $entry->dn . '" failed: ' . $update->{errorMessage};
		$self->warn;
		return undef;
	}

	$entry->dump if $args{dump};
	return 1;
} ## end sub userCNadd

=head2 userCNremove

Remove a C<cn> value from a user entry.  Refuses to remove the last
remaining value since C<cn> is a MUST attribute of posixAccount.

=head3 args hash

=head4 user

The username (uid) to act on. Required.

=head4 cn

The CN value to remove. Required.

=head4 dump

Call the dump method on the entry afterwards.

    $pt->userCNremove({ user => 'jsmith', cn => 'J Smith' });

=cut

sub userCNremove {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{cn} ) || $args{cn} eq '' ) {
		$self->{error}       = 70;
		$self->{errorString} = 'No CN value specified';
		$self->warn;
		return undef;
	}

	my ( $name, $passwd, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ')(uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	my @current = $entry->get_value('cn');
	if ( @current <= 1 ) {
		$self->{error}       = 71;
		$self->{errorString} = 'Cannot remove the last cn value from "' . $args{user} . '"';
		$self->warn;
		return undef;
	}

	$entry->delete( cn => [ $args{cn} ] );

	my $update = $entry->update($ldap);
	if ( $update->{errorMessage} ne '' ) {
		$self->{error} = 34;
		$self->{errorString}
			= 'Removing cn "' . $args{cn} . '" for "' . $entry->dn . '" failed: ' . $update->{errorMessage};
		$self->warn;
		return undef;
	}

	$entry->dump if $args{dump};
	return 1;
} ## end sub userCNremove

=head2 ldapPublicKeyAvailable

Returns true if the C<ldapPublicKey> objectClass is present in the LDAP
server's schema, false if it is not loaded.  Returns C<undef> on error
(e.g. the schema subentry could not be fetched).

    if ( $pt->ldapPublicKeyAvailable ) { ... }

=cut

sub ldapPublicKeyAvailable {
	my $self = $_[0];

	$self->errorblank;

	my $ldap   = $self->connect();
	my $schema = $ldap->schema;
	if ( !defined($schema) ) {
		$self->{error}       = 72;
		$self->{errorString} = 'Could not fetch LDAP schema';
		$self->warn;
		return undef;
	}

	my $oc = $schema->objectclass('ldapPublicKey');
	return defined($oc) ? 1 : 0;
} ## end sub ldapPublicKeyAvailable

=head2 userConvertToLdapPublicKey

Add the C<ldapPublicKey> auxiliary objectClass to a user entry, enabling
storage of SSH public keys via the C<sshPublicKey> attribute.

Returns 1 on success (or if the objectClass was already present),
C<undef> on error.

=head3 args hash

=head4 user

The username (uid) to act on. Required.

=head4 dump

Call the dump method on the entry afterwards.

    $pt->userConvertToLdapPublicKey({ user => 'jsmith' });

=cut

sub userConvertToLdapPublicKey {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	my ( $name, $passwd, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ')(uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	# Already has the objectClass — nothing to do
	my %oc_map = map { lc($_) => 1 } $entry->get_value('objectClass');
	if ( $oc_map{ldappublickey} ) {
		$self->{error}       = 74;
		$self->{errorString} = 'The user "' . $args{user} . '" already has the ldapPublicKey objectClass';
		$self->warn;
		return undef;
	}

	# ldapPublicKey is AUXILIARY — a simple modify is sufficient
	$entry->add( objectClass => 'ldapPublicKey' );

	my $update = $entry->update($ldap);
	if ( $update->{errorMessage} ne '' ) {
		$self->{error} = 34;
		$self->{errorString}
			= 'Adding ldapPublicKey objectClass to "' . $entry->dn . '" failed: ' . $update->{errorMessage};
		$self->warn;
		return undef;
	}

	$entry->dump if $args{dump};
	return 1;
} ## end sub userConvertToLdapPublicKey

=head2 userSSHPublicKeyAdd

Add an SSH public key to a user.  The user must already have the
C<ldapPublicKey> objectClass; call C<userConvertToLdapPublicKey> first
if needed.

=head3 args hash

=head4 user

The username (uid) to act on. Required.

=head4 key

The SSH public key string to add. Required.

=head4 dump

Call the dump method on the entry afterwards.

    $pt->userSSHPublicKeyAdd({ user => 'jsmith', key => 'ssh-ed25519 AAAA...' });

=cut

sub userSSHPublicKeyAdd {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{key} ) || $args{key} eq '' ) {
		$self->{error}       = 73;
		$self->{errorString} = 'No SSH public key specified';
		$self->warn;
		return undef;
	}

	if ( $args{key} =~ /[\n\r]/ ) {
		$self->{error}       = 73;
		$self->{errorString} = 'SSH public key must not contain newlines';
		$self->warn;
		return undef;
	}

	my ( $name, $passwd, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ')(uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	my %oc_map = map { lc($_) => 1 } $entry->get_value('objectClass');
	if ( !$oc_map{ldappublickey} ) {
		$self->{error}       = 72;
		$self->{errorString} = 'The user "' . $args{user} . '" does not have the ldapPublicKey objectClass';
		$self->warn;
		return undef;
	}

	$entry->add( sshPublicKey => $args{key} );

	my $update = $entry->update($ldap);
	if ( $update->{errorMessage} ne '' ) {
		$self->{error}       = 34;
		$self->{errorString} = 'Adding sshPublicKey for "' . $entry->dn . '" failed: ' . $update->{errorMessage};
		$self->warn;
		return undef;
	}

	$entry->dump if $args{dump};
	return 1;
} ## end sub userSSHPublicKeyAdd

=head2 userSSHPublicKeyRemove

Remove a specific SSH public key from a user.

=head3 args hash

=head4 user

The username (uid) to act on. Required.

=head4 key

The SSH public key string to remove. Required.

=head4 dump

Call the dump method on the entry afterwards.

    $pt->userSSHPublicKeyRemove({ user => 'jsmith', key => 'ssh-ed25519 AAAA...' });

=cut

sub userSSHPublicKeyRemove {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{key} ) || $args{key} eq '' ) {
		$self->{error}       = 73;
		$self->{errorString} = 'No SSH public key specified';
		$self->warn;
		return undef;
	}

	my ( $name, $passwd, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'The user "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ')(uidNumber=' . $uid . '))'
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	$entry->delete( sshPublicKey => [ $args{key} ] );

	my $update = $entry->update($ldap);
	if ( $update->{errorMessage} ne '' ) {
		$self->{error}       = 34;
		$self->{errorString} = 'Removing sshPublicKey for "' . $entry->dn . '" failed: ' . $update->{errorMessage};
		$self->warn;
		return undef;
	}

	$entry->dump if $args{dump};
	return 1;
} ## end sub userSSHPublicKeyRemove

# Format a Net::LDAP::Entry as a human-readable string for diagnostic output.
sub _entryToString {
	my ($entry) = @_;
	my $out = 'dn: ' . $entry->dn . "\n";
	for my $attr ( sort $entry->attributes ) {
		for my $val ( $entry->get_value($attr) ) {
			$out .= "  $attr: $val\n";
		}
	}
	return $out;
} ## end sub _entryToString

=head2 userVerifyPassword

Verify a user's password by attempting to bind to LDAP as that user.
Unlike L</userSetPass>, this method does not require NSS and searches
by C<uid> only, making it suitable for self-service portals.

=head3 args hash

=head4 user

The username (uid) to verify.

=head4 password

The password to verify.

    my $ok = $pt->userVerifyPassword({ user => 'jdoe', password => 'secret' });
    if ( !$ok ) {
        # $pt->error == 75 means invalid credentials
    }

=cut

sub userVerifyPassword {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{password} ) ) {
		$self->{error}       = 35;
		$self->{errorString} = 'No password specified';
		$self->warn;
		return undef;
	}

	# Search for the user entry by uid only (no getpwnam)
	my $ldap = $self->connect();
	return undef if $self->error;

	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(uid=' . $args{user} . ')',
		attrs  => ['dn'],
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	# Attempt a bind as the user to verify credentials
	my $user_ldap = Net::LDAP->new( $self->{ini}->{''}->{server}, port => $self->{ini}->{''}->{port} );
	if ( !defined($user_ldap) ) {
		$self->{error}       = 11;
		$self->{errorString} = 'Failed to connect to LDAP server for credential verification';
		$self->warn;
		return undef;
	}

	my $bind = $user_ldap->bind( $entry->dn, password => $args{password} );
	if ( $bind->code == 49 ) {
		$self->{error}       = 75;
		$self->{errorString} = 'Authentication failed for "' . $args{user} . '"';
		$self->warn;
		return undef;
	}
	if ( $bind->code != 0 ) {
		$self->{error}       = 13;
		$self->{errorString} = 'LDAP bind failed: ' . $bind->error;
		$self->warn;
		return undef;
	}

	return 1;
} ## end sub userVerifyPassword

=head2 userSetPassSelf

Set a user's password without requiring NSS (C<getpwnam>). Searches
by C<uid> only. Intended for self-service and password-reset flows.

=head3 args hash

=head4 user

The username (uid) of the user whose password should be changed.

=head4 pass

The new password.

    $pt->userSetPassSelf({ user => 'jdoe', pass => 'newpass' });

=cut

sub userSetPassSelf {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{pass} ) ) {
		$self->{error}       = 35;
		$self->{errorString} = 'No password specified.';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	return undef if $self->error;

	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(uid=' . $args{user} . ')',
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	my $mesg2 = $ldap->set_password( user => $entry->dn, newpasswd => $args{pass} );
	if ( $mesg2->{errorMessage} ne '' ) {
		$self->{error}       = 36;
		$self->{errorString} = 'Setting password for "' . $entry->dn . '" failed: ' . $mesg2->{errorMessage};
		$self->warn;
		return undef;
	}

	return 1;
} ## end sub userSetPassSelf

=head2 userSelfInfo

Return a hashref of user attributes useful for a self-service portal.
Searches by C<uid> only (no NSS dependency).

Returned keys:

=over 4

=item cn

Arrayref of CN values.

=item mail

The C<mail> attribute (may be undef).

=item displayName

The C<displayName> attribute (may be undef).

=item sshPublicKey

Arrayref of C<sshPublicKey> values.

=item objectClasses

Hashref mapping lowercase objectClass names to 1.

=back

    my $info = $pt->userSelfInfo({ user => 'jdoe' });

=cut

sub userSelfInfo {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	return undef if $self->error;

	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(uid=' . $args{user} . ')',
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	my %info;
	$info{cn}                   = [ $entry->get_value('cn') ];
	$info{mail}                 = $entry->get_value('mail');
	$info{displayName}          = $entry->get_value('displayName');
	$info{sshPublicKey}         = [ $entry->get_value('sshPublicKey') ];
	$info{objectClasses}        = { map { lc($_) => 1 } $entry->get_value('objectClass') };
	$info{totpStatus}           = $entry->get_value('totpStatus');
	$info{totpEnrolledDate}     = $entry->get_value('totpEnrolledDate');
	$info{totpScratchCodeCount} = () = $entry->get_value('totpScratchCode');
	$info{totpAlgorithm}        = $entry->get_value('totpAlgorithm');
	$info{totpPeriod}           = $entry->get_value('totpPeriod');
	$info{totpDigits}           = $entry->get_value('totpDigits');

	return \%info;
} ## end sub userSelfInfo

=head2 userSSHPublicKeyAddSelf

Add an SSH public key to a user's LDAP entry without requiring NSS.
Searches by C<uid> only.

=head3 args hash

=head4 user

The username (uid).

=head4 key

The SSH public key string to add. Must not contain newlines.

    $pt->userSSHPublicKeyAddSelf({ user => 'jdoe', key => 'ssh-rsa AAA...' });

=cut

sub userSSHPublicKeyAddSelf {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{key} ) || $args{key} eq '' ) {
		$self->{error}       = 73;
		$self->{errorString} = 'No SSH public key specified';
		$self->warn;
		return undef;
	}

	if ( $args{key} =~ /[\n\r]/ ) {
		$self->{error}       = 73;
		$self->{errorString} = 'SSH public key must not contain newlines';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	return undef if $self->error;

	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(uid=' . $args{user} . ')',
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	my @ocs = map { lc($_) } $entry->get_value('objectClass');
	if ( !grep { $_ eq 'ldappublickey' } @ocs ) {
		$self->{error}       = 72;
		$self->{errorString} = 'User "' . $args{user} . '" does not have the ldapPublicKey objectClass';
		$self->warn;
		return undef;
	}

	$entry->add( sshPublicKey => $args{key} );

	my $update = $entry->update($ldap);
	if ( $update->{errorMessage} ne '' ) {
		$self->{error}       = 34;
		$self->{errorString} = 'Adding sshPublicKey for "' . $entry->dn . '" failed: ' . $update->{errorMessage};
		$self->warn;
		return undef;
	}

	return 1;
} ## end sub userSSHPublicKeyAddSelf

=head2 userSSHPublicKeyRemoveSelf

Remove a specific SSH public key from a user's LDAP entry without
requiring NSS. Searches by C<uid> only.

=head3 args hash

=head4 user

The username (uid).

=head4 key

The exact SSH public key string to remove.

    $pt->userSSHPublicKeyRemoveSelf({ user => 'jdoe', key => 'ssh-rsa AAA...' });

=cut

sub userSSHPublicKeyRemoveSelf {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !defined( $args{key} ) || $args{key} eq '' ) {
		$self->{error}       = 73;
		$self->{errorString} = 'No SSH public key specified';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	return undef if $self->error;

	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(uid=' . $args{user} . ')',
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	$entry->delete( sshPublicKey => [ $args{key} ] );

	my $update = $entry->update($ldap);
	if ( $update->{errorMessage} ne '' ) {
		$self->{error}       = 34;
		$self->{errorString} = 'Removing sshPublicKey for "' . $entry->dn . '" failed: ' . $update->{errorMessage};
		$self->warn;
		return undef;
	}

	return 1;
} ## end sub userSSHPublicKeyRemoveSelf

=head2 userConvertToLdapPublicKeySelf

Add the C<ldapPublicKey> auxiliary objectClass to a user without
requiring NSS. Searches by C<uid> only.

=head3 args hash

=head4 user

The username (uid).

    $pt->userConvertToLdapPublicKeySelf({ user => 'jdoe' });

=cut

sub userConvertToLdapPublicKeySelf {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !$self->ldapPublicKeyAvailable ) {
		$self->{error}       = 72;
		$self->{errorString} = 'The ldapPublicKey schema is not available on this LDAP server';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	return undef if $self->error;

	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(uid=' . $args{user} . ')',
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for the user failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'The user "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	my @ocs = map { lc($_) } $entry->get_value('objectClass');
	if ( grep { $_ eq 'ldappublickey' } @ocs ) {
		$self->{error}       = 74;
		$self->{errorString} = 'User "' . $args{user} . '" already has the ldapPublicKey objectClass';
		$self->warn;
		return undef;
	}

	$entry->add( objectClass => 'ldapPublicKey' );

	my $update = $entry->update($ldap);
	if ( $update->{errorMessage} ne '' ) {
		$self->{error} = 34;
		$self->{errorString}
			= 'Adding ldapPublicKey objectClass for "' . $entry->dn . '" failed: ' . $update->{errorMessage};
		$self->warn;
		return undef;
	}

	return 1;
} ## end sub userConvertToLdapPublicKeySelf

=head2 smtpAvailable

Returns 1 if SMTP is configured (both C<smtpserver> and C<smtpfrom>
are non-empty), undef otherwise.

    if ( $pt->smtpAvailable ) {
        # can send email
    }

=cut

sub smtpAvailable {
	my $self = $_[0];

	$self->errorblank;

	return ( $self->{ini}->{''}->{smtpserver} ne '' && $self->{ini}->{''}->{smtpfrom} ne '' ) ? 1 : undef;
}

=head2 sendEmail

Send an email via SMTP. Returns 1 on success, undef on failure.

=head3 args hash

=head4 to

Recipient email address.

=head4 subject

Email subject line.

=head4 body

Plain-text email body.

    $pt->sendEmail({
        to      => 'user@example.com',
        subject => 'Password Reset',
        body    => "Click here: https://...\n",
    });

=cut

sub sendEmail {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	$self->errorblank;

	if ( !$self->smtpAvailable ) {
		$self->{error}       = 76;
		$self->{errorString} = 'SMTP is not configured (smtpserver and smtpfrom must be set)';
		$self->warn;
		return undef;
	}

	my $tls_mode = lc( $self->{ini}->{''}->{smtptls} // '' );
	my $smtp     = Net::SMTP->new(
		$self->{ini}->{''}->{smtpserver},
		Port    => $self->{ini}->{''}->{smtpport},
		Timeout => 30,
		( $tls_mode eq 'ssl' ? ( SSL => 1 ) : () ),
	);
	if ( !defined($smtp) ) {
		$self->{error}       = 77;
		$self->{errorString} = 'Failed to connect to SMTP server "' . $self->{ini}->{''}->{smtpserver} . '"';
		$self->warn;
		return undef;
	}

	if ( $tls_mode eq 'starttls' ) {
		if ( !$smtp->starttls ) {
			$self->{error}       = 77;
			$self->{errorString} = 'STARTTLS negotiation failed with "' . $self->{ini}->{''}->{smtpserver} . '"';
			$smtp->quit;
			$self->warn;
			return undef;
		}
	}

	if ( $self->{ini}->{''}->{smtpuser} ne '' && $self->{ini}->{''}->{smtppass} ne '' ) {
		if ( !$smtp->auth( $self->{ini}->{''}->{smtpuser}, $self->{ini}->{''}->{smtppass} ) ) {
			$self->{error}       = 77;
			$self->{errorString} = 'SMTP authentication failed for user "' . $self->{ini}->{''}->{smtpuser} . '"';
			$smtp->quit;
			$self->warn;
			return undef;
		}
	}

	my $from    = $self->{ini}->{''}->{smtpfrom};
	my $to      = $args{to}      // '';
	my $subject = $args{subject} // '(no subject)';
	my $body    = $args{body}    // '';

	if ( !$smtp->mail($from) ) {
		$self->{error}       = 78;
		$self->{errorString} = 'SMTP MAIL FROM failed';
		$smtp->quit;
		$self->warn;
		return undef;
	}
	if ( !$smtp->to($to) ) {
		$self->{error}       = 78;
		$self->{errorString} = 'SMTP RCPT TO failed for "' . $to . '"';
		$smtp->quit;
		$self->warn;
		return undef;
	}
	if ( !$smtp->data ) {
		$self->{error}       = 78;
		$self->{errorString} = 'SMTP DATA command failed';
		$smtp->quit;
		$self->warn;
		return undef;
	}
	$smtp->datasend("From: $from\r\n");
	$smtp->datasend("To: $to\r\n");
	$smtp->datasend("Subject: $subject\r\n");
	$smtp->datasend("MIME-Version: 1.0\r\n");
	$smtp->datasend("Content-Type: text/plain; charset=UTF-8\r\n");
	$smtp->datasend("\r\n");
	$smtp->datasend($body);

	if ( !$smtp->dataend ) {
		$self->{error}       = 78;
		$self->{errorString} = 'SMTP dataend failed';
		$smtp->quit;
		$self->warn;
		return undef;
	}
	$smtp->quit;

	return 1;
} ## end sub sendEmail

# Valid totpStatus values
my %_TOTP_STATUS_OK = map { $_ => 1 } qw( none pending active disabled bypassed );

# Valid totpAlgorithm values (stored and passed to Authen::TOTP in upper-case)
my %_TOTP_ALGORITHM_OK = map { $_ => 1 } qw( SHA1 SHA256 SHA512 );

# Valid totpDigits values
my %_TOTP_DIGITS_OK = map { $_ => 1 } ( 6, 8 );

# Build a GeneralizedTime string for the current UTC time.
sub _generalizedTimeNow {
	my @t = gmtime(time);
	return sprintf( '%04d%02d%02d%02d%02d%02dZ', $t[5] + 1900, $t[4] + 1, $t[3], $t[2], $t[1], $t[0] );
}

=head2 totpSchemaAvailable

Returns 1 if the C<totpUser> objectClass is present in the LDAP
server's schema, undef otherwise.

    if ( $pt->totpSchemaAvailable ) {
        # TOTP schema is loaded
    }

=cut

sub totpSchemaAvailable {
	my $self = $_[0];

	$self->errorblank;

	my $ldap = $self->connect();
	return undef if $self->error;

	my $schema = $ldap->schema;
	return undef unless defined $schema;

	my $oc = $schema->objectclass('totpUser');
	return ( defined $oc && defined $oc->{name} ) ? 1 : undef;
} ## end sub totpSchemaAvailable

=head2 userConvertToTotp

Add the C<totpUser> auxiliary objectClass to a user entry.

=head3 args hash

=head4 user

The username (uid).

    $pt->userConvertToTotp({ user => 'jdoe' });

=cut

sub userConvertToTotp {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) { %args = %{ $_[1] } }

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !$self->totpSchemaAvailable ) {
		$self->{error}       = 79;
		$self->{errorString} = 'The totpUser schema is not available on this LDAP server';
		$self->warn;
		return undef;
	}

	my ( $name, undef, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'User "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	return undef if $self->error;

	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ')(uidNumber=' . $uid . '))',
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for user "' . $args{user} . '" failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'User "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	my @ocs = map { lc($_) } $entry->get_value('objectClass');
	if ( grep { $_ eq 'totpuser' } @ocs ) {
		$self->{error}       = 80;
		$self->{errorString} = 'User "' . $args{user} . '" already has the totpUser objectClass';
		$self->warn;
		return undef;
	}

	$entry->add( objectClass => 'totpUser' );
	my $update = $entry->update($ldap);
	if ( $update->{errorMessage} ne '' ) {
		$self->{error} = 34;
		$self->{errorString}
			= 'Adding totpUser objectClass for "' . $entry->dn . '" failed: ' . $update->{errorMessage};
		$self->warn;
		return undef;
	}

	return 1;
} ## end sub userConvertToTotp

=head2 userTotpInfoGet

Return a hashref of TOTP-related attributes for a user.

Returned keys:

=over 4

=item totpSecret

The Base32-encoded TOTP secret (may be undef).

=item totpStatus

Enrollment status string (may be undef).

=item totpEnrolledDate

GeneralizedTime enrollment timestamp (may be undef).

=item totpScratchCodes

Arrayref of current scratch codes.

=item hasTotpUser

1 if the entry carries the C<totpUser> objectClass, 0 otherwise.

=back


    my $info = $pt->userTotpInfoGet({ user => 'jdoe' });

=cut

sub userTotpInfoGet {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) { %args = %{ $_[1] } }

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	my ( $name, undef, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'User "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	return undef if $self->error;

	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ')(uidNumber=' . $uid . '))',
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for user "' . $args{user} . '" failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'User "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	my @ocs = map { lc($_) } $entry->get_value('objectClass');
	return {
		hasTotpUser      => ( grep { $_ eq 'totpuser' } @ocs ) ? 1 : 0,
		totpSecret       => scalar( $entry->get_value('totpSecret') ),
		totpStatus       => scalar( $entry->get_value('totpStatus') ),
		totpEnrolledDate => scalar( $entry->get_value('totpEnrolledDate') ),
		totpScratchCodes => [ $entry->get_value('totpScratchCode') ],
		totpAlgorithm    => scalar( $entry->get_value('totpAlgorithm') ),
		totpPeriod       => scalar( $entry->get_value('totpPeriod') ),
		totpDigits       => scalar( $entry->get_value('totpDigits') ),
	};
} ## end sub userTotpInfoGet

=head2 userTotpSecretSet

Set the C<totpSecret> attribute on a user.

=head3 args hash

=head4 user

The username (uid).

=head4 secret

The Base32-encoded TOTP secret string.

    $pt->userTotpSecretSet({ user => 'jdoe', secret => 'JBSWY3DPEHPK3PXP' });

=cut

sub userTotpSecretSet {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) { %args = %{ $_[1] } }

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}
	if ( !defined( $args{secret} ) || $args{secret} eq '' ) {
		$self->{error}       = 81;
		$self->{errorString} = 'No TOTP secret specified';
		$self->warn;
		return undef;
	}

	my ( $name, undef, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'User "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	return undef if $self->error;

	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ')(uidNumber=' . $uid . '))',
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for user "' . $args{user} . '" failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'User "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	$entry->replace( totpSecret => $args{secret} );
	my $update = $entry->update($ldap);
	if ( $update->{errorMessage} ne '' ) {
		$self->{error}       = 34;
		$self->{errorString} = 'Setting totpSecret for "' . $entry->dn . '" failed: ' . $update->{errorMessage};
		$self->warn;
		return undef;
	}

	return 1;
} ## end sub userTotpSecretSet

=head2 userTotpSecretRemove

Remove the C<totpSecret> from a user's entry and clear the associated
algorithm, digits, and period attributes. Sets C<totpStatus> to C<none>
and clears C<totpEnrolledDate>.

=head3 args hash

=head4 user

The username (uid).

    $pt->userTotpSecretRemove({ user => 'jdoe' });

=cut

sub userTotpSecretRemove {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) { %args = %{ $_[1] } }

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	my ( $name, undef, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'User "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	return undef if $self->error;

	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ')(uidNumber=' . $uid . '))',
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for user "' . $args{user} . '" failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'User "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	for my $attr (qw( totpSecret totpAlgorithm totpDigits totpPeriod totpEnrolledDate totpScratchCode )) {
		$entry->delete($attr) if defined scalar( $entry->get_value($attr) );
	}
	$entry->replace( totpStatus => 'none' );

	my $update = $entry->update($ldap);
	if ( $update->{errorMessage} ne '' ) {
		$self->{error}       = 34;
		$self->{errorString} = 'Removing TOTP secret for "' . $entry->dn . '" failed: ' . $update->{errorMessage};
		$self->warn;
		return undef;
	}

	return 1;
} ## end sub userTotpSecretRemove

=head2 userTotpStatusSet

Set the C<totpStatus> attribute on a user. Valid values are
C<none>, C<pending>, C<active>, C<disabled>, C<bypassed>.

=head3 args hash

=head4 user

The username (uid).

=head4 status

The status string.

    $pt->userTotpStatusSet({ user => 'jdoe', status => 'active' });

=cut

sub userTotpStatusSet {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) { %args = %{ $_[1] } }

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}
	if ( !defined( $args{status} ) || !$_TOTP_STATUS_OK{ lc( $args{status} ) } ) {
		$self->{error} = 82;
		$self->{errorString}
			= 'Invalid or missing totpStatus; must be one of: ' . join( ', ', sort keys %_TOTP_STATUS_OK );
		$self->warn;
		return undef;
	}

	my ( $name, undef, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'User "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	return undef if $self->error;

	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ')(uidNumber=' . $uid . '))',
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for user "' . $args{user} . '" failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'User "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	$entry->replace( totpStatus => lc( $args{status} ) );
	if ( lc( $args{status} ) eq 'pending' && defined scalar( $entry->get_value('totpEnrolledDate') ) ) {
		$entry->delete('totpEnrolledDate');
	}
	my $update = $entry->update($ldap);
	if ( $update->{errorMessage} ne '' ) {
		$self->{error}       = 34;
		$self->{errorString} = 'Setting totpStatus for "' . $entry->dn . '" failed: ' . $update->{errorMessage};
		$self->warn;
		return undef;
	}

	return 1;
} ## end sub userTotpStatusSet

=head2 userTotpAlgorithmSet

Set the C<totpAlgorithm> attribute on a user. Valid values are
C<SHA1>, C<SHA256>, C<SHA512>.

=head3 args hash

=head4 user

The username (uid).

=head4 algorithm

The algorithm string (case-insensitive).

    $pt->userTotpAlgorithmSet({ user => 'jdoe', algorithm => 'SHA256' });

=cut

sub userTotpAlgorithmSet {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) { %args = %{ $_[1] } }

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}
	if ( !defined( $args{algorithm} ) || !$_TOTP_ALGORITHM_OK{ uc( $args{algorithm} ) } ) {
		$self->{error} = 86;
		$self->{errorString}
			= 'Invalid or missing totpAlgorithm; must be one of: ' . join( ', ', sort keys %_TOTP_ALGORITHM_OK );
		$self->warn;
		return undef;
	}

	my ( $name, undef, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'User "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	return undef if $self->error;

	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ')(uidNumber=' . $uid . '))',
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for user "' . $args{user} . '" failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'User "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	$entry->replace( totpAlgorithm => uc( $args{algorithm} ) );
	my $update = $entry->update($ldap);
	if ( $update->{errorMessage} ne '' ) {
		$self->{error}       = 34;
		$self->{errorString} = 'Setting totpAlgorithm for "' . $entry->dn . '" failed: ' . $update->{errorMessage};
		$self->warn;
		return undef;
	}

	return 1;
} ## end sub userTotpAlgorithmSet

=head2 userTotpPeriodSet

Set the C<totpPeriod> attribute on a user. Must be a positive integer;
30 is the standard time step.

=head3 args hash

=head4 user

The username (uid).

=head4 period

Time step in seconds (positive integer).

    $pt->userTotpPeriodSet({ user => 'jdoe', period => 30 });

=cut

sub userTotpPeriodSet {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) { %args = %{ $_[1] } }

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}
	my $period = defined( $args{period} ) ? int( $args{period} ) : undef;
	if ( !defined($period) || $period < 1 ) {
		$self->{error}       = 88;
		$self->{errorString} = 'Invalid or missing totpPeriod; must be a positive integer';
		$self->warn;
		return undef;
	}

	my ( $name, undef, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'User "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	return undef if $self->error;

	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ')(uidNumber=' . $uid . '))',
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for user "' . $args{user} . '" failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'User "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	$entry->replace( totpPeriod => $period );
	my $update = $entry->update($ldap);
	if ( $update->{errorMessage} ne '' ) {
		$self->{error}       = 34;
		$self->{errorString} = 'Setting totpPeriod for "' . $entry->dn . '" failed: ' . $update->{errorMessage};
		$self->warn;
		return undef;
	}

	return 1;
} ## end sub userTotpPeriodSet

=head2 userTotpDigitsSet

Set the C<totpDigits> attribute on a user. Valid values are 6 or 8.

=head3 args hash

=head4 user

The username (uid).

=head4 digits

Number of OTP digits (6 or 8).

    $pt->userTotpDigitsSet({ user => 'jdoe', digits => 6 });

=cut

sub userTotpDigitsSet {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) { %args = %{ $_[1] } }

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}
	my $digits = defined( $args{digits} ) ? int( $args{digits} ) : undef;
	if ( !defined($digits) || !$_TOTP_DIGITS_OK{$digits} ) {
		$self->{error} = 87;
		$self->{errorString}
			= 'Invalid or missing totpDigits; must be one of: ' . join( ', ', sort keys %_TOTP_DIGITS_OK );
		$self->warn;
		return undef;
	}

	my ( $name, undef, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'User "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	return undef if $self->error;

	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ')(uidNumber=' . $uid . '))',
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for user "' . $args{user} . '" failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'User "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	$entry->replace( totpDigits => $digits );
	my $update = $entry->update($ldap);
	if ( $update->{errorMessage} ne '' ) {
		$self->{error}       = 34;
		$self->{errorString} = 'Setting totpDigits for "' . $entry->dn . '" failed: ' . $update->{errorMessage};
		$self->warn;
		return undef;
	}

	return 1;
} ## end sub userTotpDigitsSet

=head2 userTotpEnrolledDateSet

Set the C<totpEnrolledDate> attribute on a user to the current UTC
time in GeneralizedTime format.

=head3 args hash

=head4 user

The username (uid).

    $pt->userTotpEnrolledDateSet({ user => 'jdoe' });

=cut

sub userTotpEnrolledDateSet {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) { %args = %{ $_[1] } }

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	my ( $name, undef, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'User "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	return undef if $self->error;

	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ')(uidNumber=' . $uid . '))',
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for user "' . $args{user} . '" failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'User "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	$entry->replace( totpEnrolledDate => _generalizedTimeNow() );
	my $update = $entry->update($ldap);
	if ( $update->{errorMessage} ne '' ) {
		$self->{error}       = 34;
		$self->{errorString} = 'Setting totpEnrolledDate for "' . $entry->dn . '" failed: ' . $update->{errorMessage};
		$self->warn;
		return undef;
	}

	return 1;
} ## end sub userTotpEnrolledDateSet

=head2 userTotpScratchCodeAdd

Add one or more scratch/backup codes to a user's C<totpScratchCode> attribute.

=head3 args hash

=head4 user

The username (uid).

=head4 code

A single scratch code string, or an array ref of scratch code strings. Each
code must match the length defined by C<totpDigits> for the user (default 6).

    $pt->userTotpScratchCodeAdd({ user => 'jdoe', code => '123456' });
    $pt->userTotpScratchCodeAdd({ user => 'jdoe', code => ['123456', '654321'] });

=cut

sub userTotpScratchCodeAdd {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) { %args = %{ $_[1] } }

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}
	if ( !defined( $args{code} ) || ( ref( $args{code} ) eq '' && $args{code} eq '' ) ) {
		$self->{error}       = 83;
		$self->{errorString} = 'No scratch code specified';
		$self->warn;
		return undef;
	}

	my @codes = ref( $args{code} ) eq 'ARRAY' ? @{ $args{code} } : ( $args{code} );
	if ( !@codes ) {
		$self->{error}       = 83;
		$self->{errorString} = 'No scratch code specified';
		$self->warn;
		return undef;
	}

	my ( $name, undef, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'User "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	return undef if $self->error;

	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ')(uidNumber=' . $uid . '))',
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for user "' . $args{user} . '" failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'User "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	my $expected_len = scalar( $entry->get_value('totpDigits') ) // 6;
	for my $code (@codes) {
		if ( length($code) != $expected_len ) {
			$self->{error}       = 87;
			$self->{errorString} = 'Scratch code must be ' . $expected_len . ' digits (totpDigits for this user)';
			$self->warn;
			return undef;
		}
	}

	my $max           = $self->{ini}->{''}->{totpMaxScratchCodes};
	my $current_count = () = $entry->get_value('totpScratchCode');
	if ( $current_count + scalar(@codes) > $max ) {
		$self->{error} = 89;
		$self->{errorString}
			= 'Adding '
			. scalar(@codes)
			. ' scratch code(s) would exceed the maximum of '
			. $max
			. ' for user "'
			. $args{user} . '"';
		$self->warn;
		return undef;
	} ## end if ( $current_count + scalar(@codes) > $max)

	$entry->add( totpScratchCode => \@codes );
	my $update = $entry->update($ldap);
	if ( $update->{errorMessage} ne '' ) {
		$self->{error}       = 34;
		$self->{errorString} = 'Adding totpScratchCode for "' . $entry->dn . '" failed: ' . $update->{errorMessage};
		$self->warn;
		return undef;
	}

	return 1;
} ## end sub userTotpScratchCodeAdd

=head2 userTotpScratchCodesReplace

Remove all existing scratch codes for a user and replace them with freshly
generated ones. Returns an array ref of the new plaintext codes on success,
or C<undef> on error.

The codes are generated using C<totpDigits> (default 6) zero-padded random
integers. The number of codes generated is controlled by the optional C<count>
argument (defaults to C<totpMaxScratchCodes>). Requesting more than
C<totpMaxScratchCodes> is an error.

=head3 args hash

=head4 user

The username (uid).

=head4 count

Number of scratch codes to generate. Optional, defaults to 5.

    my $codes = $pt->userTotpScratchCodesReplace({ user => 'jdoe' });
    my $codes = $pt->userTotpScratchCodesReplace({ user => 'jdoe', count => 8 });

=cut

sub userTotpScratchCodesReplace {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) { %args = %{ $_[1] } }

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	my ( $name, undef, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'User "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	return undef if $self->error;

	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ')(uidNumber=' . $uid . '))',
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for user "' . $args{user} . '" failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'User "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	my $digits = scalar( $entry->get_value('totpDigits') ) // 6;
	my $max    = $self->{ini}->{''}->{totpMaxScratchCodes};
	my $count  = $args{count} // $max;
	if ( $count > $max ) {
		$self->{error}       = 89;
		$self->{errorString} = 'Requested scratch code count (' . $count . ') exceeds the maximum of ' . $max;
		$self->warn;
		return undef;
	}

	my @new_codes;
	for ( 1 .. $count ) {
		push @new_codes, sprintf( '%0*d', $digits, int( rand( 10**$digits ) ) );
	}

	# Remove existing scratch codes if present
	if ( defined scalar( $entry->get_value('totpScratchCode') ) ) {
		$entry->delete('totpScratchCode');
	}

	$entry->add( totpScratchCode => \@new_codes );
	my $update = $entry->update($ldap);
	if ( $update->{errorMessage} ne '' ) {
		$self->{error}       = 34;
		$self->{errorString} = 'Replacing totpScratchCode for "' . $entry->dn . '" failed: ' . $update->{errorMessage};
		$self->warn;
		return undef;
	}

	return \@new_codes;
} ## end sub userTotpScratchCodesReplace

=head2 userTotpScratchCodeRemove

Remove a specific scratch code from a user.

=head3 args hash

=head4 user

The username (uid).

=head4 code

The exact scratch code string to remove.

    $pt->userTotpScratchCodeRemove({ user => 'jdoe', code => '12345678' });

=cut

sub userTotpScratchCodeRemove {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) { %args = %{ $_[1] } }

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}
	if ( !defined( $args{code} ) || $args{code} eq '' ) {
		$self->{error}       = 83;
		$self->{errorString} = 'No scratch code specified';
		$self->warn;
		return undef;
	}

	my ( $name, undef, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'User "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	return undef if $self->error;

	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ')(uidNumber=' . $uid . '))',
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for user "' . $args{user} . '" failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'User "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	$entry->delete( totpScratchCode => [ $args{code} ] );
	my $update = $entry->update($ldap);
	if ( $update->{errorMessage} ne '' ) {
		$self->{error}       = 34;
		$self->{errorString} = 'Removing totpScratchCode for "' . $entry->dn . '" failed: ' . $update->{errorMessage};
		$self->warn;
		return undef;
	}

	return 1;
} ## end sub userTotpScratchCodeRemove

=head2 groupConvertToMfa

Add the C<mfaGroup> auxiliary objectClass to a group entry.

=head3 args hash

=head4 group

The group name.

    $pt->groupConvertToMfa({ group => 'engineers' });

=cut

sub groupConvertToMfa {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) { %args = %{ $_[1] } }

	$self->errorblank;

	if ( !defined( $args{group} ) ) {
		$self->{error}       = 6;
		$self->{errorString} = 'No group name specified';
		$self->warn;
		return undef;
	}

	if ( !$self->totpSchemaAvailable ) {
		$self->{error}       = 79;
		$self->{errorString} = 'The totpUser schema is not available on this LDAP server';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	return undef if $self->error;

	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{groupbase},
		filter => '(cn=' . $args{group} . ')',
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 27;
		$self->{errorString} = 'Fetching the entry for group "' . $args{group} . '" failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 14;
		$self->{errorString}
			= 'Group "' . $args{group} . '" does not exist under "' . $self->{ini}->{''}->{groupbase} . '"';
		$self->warn;
		return undef;
	}

	my @ocs = map { lc($_) } $entry->get_value('objectClass');
	if ( grep { $_ eq 'mfagroup' } @ocs ) {
		$self->{error}       = 84;
		$self->{errorString} = 'Group "' . $args{group} . '" already has the mfaGroup objectClass';
		$self->warn;
		return undef;
	}

	$entry->add( objectClass => 'mfaGroup' );
	my $update = $entry->update($ldap);
	if ( $update->{errorMessage} ne '' ) {
		$self->{error} = 34;
		$self->{errorString}
			= 'Adding mfaGroup objectClass for "' . $entry->dn . '" failed: ' . $update->{errorMessage};
		$self->warn;
		return undef;
	}

	return 1;
} ## end sub groupConvertToMfa

=head2 groupMfaRequiredSet

Set the C<mfaRequired> boolean attribute on a group.

=head3 args hash

=head4 group

The group name.

=head4 required

A true/false value. Written to LDAP as C<TRUE> or C<FALSE>.

    $pt->groupMfaRequiredSet({ group => 'engineers', required => 1 });

=cut

sub groupMfaRequiredSet {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) { %args = %{ $_[1] } }

	$self->errorblank;

	if ( !defined( $args{group} ) ) {
		$self->{error}       = 6;
		$self->{errorString} = 'No group name specified';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	return undef if $self->error;

	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{groupbase},
		filter => '(cn=' . $args{group} . ')',
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 27;
		$self->{errorString} = 'Fetching the entry for group "' . $args{group} . '" failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 14;
		$self->{errorString}
			= 'Group "' . $args{group} . '" does not exist under "' . $self->{ini}->{''}->{groupbase} . '"';
		$self->warn;
		return undef;
	}

	$entry->replace( mfaRequired => ( $args{required} ? 'TRUE' : 'FALSE' ) );
	my $update = $entry->update($ldap);
	if ( $update->{errorMessage} ne '' ) {
		$self->{error}       = 34;
		$self->{errorString} = 'Setting mfaRequired for "' . $entry->dn . '" failed: ' . $update->{errorMessage};
		$self->warn;
		return undef;
	}

	return 1;
} ## end sub groupMfaRequiredSet

=head2 groupMfaGracePeriodSet

Set the C<mfaGracePeriodDays> integer attribute on a group.

=head3 args hash

=head4 group

The group name.

=head4 days

Number of days for the grace period.

    $pt->groupMfaGracePeriodSet({ group => 'engineers', days => 7 });

=cut

sub groupMfaGracePeriodSet {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) { %args = %{ $_[1] } }

	$self->errorblank;

	if ( !defined( $args{group} ) ) {
		$self->{error}       = 6;
		$self->{errorString} = 'No group name specified';
		$self->warn;
		return undef;
	}
	if ( !defined( $args{days} ) || $args{days} !~ /^\d+$/ ) {
		$self->{error}       = 85;
		$self->{errorString} = 'No valid grace period (days) specified';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	return undef if $self->error;

	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{groupbase},
		filter => '(cn=' . $args{group} . ')',
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 27;
		$self->{errorString} = 'Fetching the entry for group "' . $args{group} . '" failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 14;
		$self->{errorString}
			= 'Group "' . $args{group} . '" does not exist under "' . $self->{ini}->{''}->{groupbase} . '"';
		$self->warn;
		return undef;
	}

	$entry->replace( mfaGracePeriodDays => $args{days} + 0 );
	my $update = $entry->update($ldap);
	if ( $update->{errorMessage} ne '' ) {
		$self->{error}       = 34;
		$self->{errorString} = 'Setting mfaGracePeriodDays for "' . $entry->dn . '" failed: ' . $update->{errorMessage};
		$self->warn;
		return undef;
	}

	return 1;
} ## end sub groupMfaGracePeriodSet

=head2 groupMfaInfoGet

Return a hashref of MFA policy attributes for a group.

Returned keys:

=over 4

=item hasMfaGroup

1 if the group carries the C<mfaGroup> objectClass, 0 otherwise.

=item mfaRequired

Boolean string from LDAP (C<TRUE>/C<FALSE>), or undef.

=item mfaGracePeriodDays

Integer, or undef.

=back

    my $info = $pt->groupMfaInfoGet({ group => 'engineers' });

=cut

sub groupMfaInfoGet {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) { %args = %{ $_[1] } }

	$self->errorblank;

	if ( !defined( $args{group} ) ) {
		$self->{error}       = 6;
		$self->{errorString} = 'No group name specified';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	return undef if $self->error;

	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{groupbase},
		filter => '(cn=' . $args{group} . ')',
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 27;
		$self->{errorString} = 'Fetching the entry for group "' . $args{group} . '" failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 14;
		$self->{errorString}
			= 'Group "' . $args{group} . '" does not exist under "' . $self->{ini}->{''}->{groupbase} . '"';
		$self->warn;
		return undef;
	}

	my @ocs = map { lc($_) } $entry->get_value('objectClass');
	return {
		hasMfaGroup        => ( grep { $_ eq 'mfagroup' } @ocs ) ? 1 : 0,
		mfaRequired        => $entry->get_value('mfaRequired'),
		mfaGracePeriodDays => $entry->get_value('mfaGracePeriodDays'),
	};
} ## end sub groupMfaInfoGet

=head2 userTotpGenerateSecret

Generate a new random TOTP secret for a user, store it in LDAP, and
set C<totpStatus> to C<pending>. Returns the Base32-encoded secret
string on success so the caller can display or log it.

=head3 args hash

=head4 user

The username (uid).

    my $secret = $pt->userTotpGenerateSecret({ user => 'jdoe' });

=cut

sub userTotpGenerateSecret {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) { %args = %{ $_[1] } }

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	if ( !$self->totpSchemaAvailable ) {
		$self->{error}       = 79;
		$self->{errorString} = 'The totpUser schema is not available on this LDAP server';
		$self->warn;
		return undef;
	}

	my ( $name, undef, $uid ) = getpwnam( $args{user} );
	if ( !defined($name) ) {
		$self->{error}       = 17;
		$self->{errorString} = 'User "' . $args{user} . '" does not exist';
		$self->warn;
		return undef;
	}

	my $ldap = $self->connect();
	return undef if $self->error;

	my $mesg = $ldap->search(
		base   => $self->{ini}->{''}->{userbase},
		filter => '(&(uid=' . $args{user} . ')(uidNumber=' . $uid . '))',
	);
	if ( $mesg->{errorMessage} ne '' ) {
		$self->{error}       = 32;
		$self->{errorString} = 'Fetching the entry for user "' . $args{user} . '" failed: ' . $mesg->{errorMessage};
		$self->warn;
		return undef;
	}
	my $entry = $mesg->pop_entry;
	if ( !defined($entry) ) {
		$self->{error} = 18;
		$self->{errorString}
			= 'User "' . $args{user} . '" does not exist under "' . $self->{ini}->{''}->{userbase} . '"';
		$self->warn;
		return undef;
	}

	my $algorithm = uc( $args{algorithm} // 'SHA1' );
	if ( !$_TOTP_ALGORITHM_OK{$algorithm} ) {
		$self->{error} = 86;
		$self->{errorString}
			= 'Invalid algorithm "'
			. $args{algorithm}
			. '"; must be one of: '
			. join( ', ', sort keys %_TOTP_ALGORITHM_OK );
		$self->warn;
		return undef;
	} ## end if ( !$_TOTP_ALGORITHM_OK{$algorithm} )

	my $digits = defined( $args{digits} ) ? int( $args{digits} ) : 6;
	if ( !$_TOTP_DIGITS_OK{$digits} ) {
		$self->{error} = 87;
		$self->{errorString}
			= 'Invalid digits "' . $args{digits} . '"; must be one of: ' . join( ', ', sort keys %_TOTP_DIGITS_OK );
		$self->warn;
		return undef;
	}

	my $period = defined( $args{period} ) ? int( $args{period} ) : 30;
	if ( $period < 1 ) {
		$self->{error}       = 88;
		$self->{errorString} = 'Invalid period "' . $args{period} . '"; must be a positive integer';
		$self->warn;
		return undef;
	}

	my $gen    = Authen::TOTP->new( algorithm => $algorithm, digits => $digits, period => $period );
	my $secret = $gen->base32secret;

	$entry->replace( totpSecret    => $secret );
	$entry->replace( totpStatus    => 'pending' );
	$entry->replace( totpAlgorithm => $algorithm );
	$entry->replace( totpDigits    => $digits );
	$entry->replace( totpPeriod    => $period );

	my $update = $entry->update($ldap);
	if ( $update->{errorMessage} ne '' ) {
		$self->{error}       = 34;
		$self->{errorString} = 'Storing TOTP secret for "' . $entry->dn . '" failed: ' . $update->{errorMessage};
		$self->warn;
		return undef;
	}

	return $secret;
} ## end sub userTotpGenerateSecret

=head2 userTotpVerify

Verify a user-supplied code against the TOTP secret stored in LDAP, or
against the user's stored scratch codes.

If the code matches the TOTP secret, returns 1.

If the code matches a scratch code, the matching C<totpScratchCode> value is
removed from the user's LDAP entry and 1 is returned. If the removal fails,
returns 0 with the error set.

Returns C<undef> without setting an error if neither check succeeds.

=head3 args hash

=head4 user

The username (uid).

=head4 code

The TOTP or scratch code to verify.

=head4 tolerance

Number of time steps either side of the current time to accept for TOTP.
Defaults to 1 (i.e. accepts codes from +-30 s).

    if ( $pt->userTotpVerify({ user => 'jdoe', code => '123456' }) ) {
        # valid
    }

=cut

sub userTotpVerify {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) { %args = %{ $_[1] } }

	$self->errorblank;

	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}
	if ( !defined( $args{code} ) || $args{code} eq '' ) {
		$self->{error}       = 83;
		$self->{errorString} = 'No TOTP code specified';
		$self->warn;
		return undef;
	}

	my $info = $self->userTotpInfoGet( { user => $args{user} } );
	return undef if $self->error;

	my $secret = $info->{totpSecret};
	if ( !defined $secret ) {
		$self->{error}       = 81;
		$self->{errorString} = 'No TOTP secret is set for user "' . $args{user} . '"';
		$self->warn;
		return undef;
	}

	# Try TOTP validation first
	my $algorithm = uc( $info->{totpAlgorithm} // 'SHA1' );
	my $digits    = $info->{totpDigits} // 6;
	my $period    = $info->{totpPeriod} // 30;
	my $gen
		= Authen::TOTP->new( base32secret => $secret, algorithm => $algorithm, digits => $digits, period => $period );
	my $tolerance = defined( $args{tolerance} ) ? $args{tolerance} : 1;
	my $valid     = eval { $gen->validate_otp( otp => $args{code}, tolerance => $tolerance ) };
	return 1 if !$@ && $valid;

	# Try scratch codes
	my @scratch_codes = @{ $info->{totpScratchCodes} // [] };
	my ($matched_code) = grep { $_ eq $args{code} } @scratch_codes;
	if ( defined $matched_code ) {
		$self->userTotpScratchCodeRemove( { user => $args{user}, code => $matched_code } );
		if ( $self->error ) {
			$self->{errorString}
				= 'Could not remove used scratch code for user "' . $args{user} . '": ' . $self->errorString;
			$self->warn;
			return 0;
		}
		return 1;
	} ## end if ( defined $matched_code )

	return undef;
} ## end sub userTotpVerify

=head2 totpURI

Build and return the C<otpauth://totp/...> URI for a user's TOTP secret.
No LDAP interaction — the caller supplies the already-fetched values.

=head3 args hash

=head4 secret

The Base32-encoded TOTP secret (as stored in LDAP).

=head4 user

The account label shown in the authenticator app.

=head4 issuer

The issuer name. Defaults to the C<totpissuer> config value.

=head4 algorithm

HMAC algorithm. Defaults to C<SHA1>.

=head4 period

Time step in seconds. Defaults to 30.

=head4 digits

OTP length. Defaults to 6.

    my $uri = $pt->totpURI({ secret => $secret, user => 'jdoe' });

=cut

sub totpURI {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) { %args = %{ $_[1] } }

	$self->errorblank;

	if ( !defined( $args{secret} ) || $args{secret} eq '' ) {
		$self->{error}       = 81;
		$self->{errorString} = 'No TOTP secret specified';
		$self->warn;
		return undef;
	}
	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	my $issuer    = $args{issuer} // $self->{ini}->{''}->{totpissuer};
	my $algorithm = uc( $args{algorithm} // 'SHA1' );
	my $digits    = $args{digits} // 6;
	my $period    = $args{period} // 30;

	my $gen = Authen::TOTP->new(
		base32secret => $args{secret},
		algorithm    => $algorithm,
		digits       => $digits,
		period       => $period
	);
	return $gen->generate_otp( user => $args{user}, issuer => $issuer );
} ## end sub totpURI

=head2 totpQRCodeBase64

Generate a QR code PNG for a C<otpauth://> URI and return it as a
Base64-encoded string (suitable for embedding in an HTML data URI).
No LDAP interaction - the caller supplies the already-fetched secret.

=head3 args hash

=head4 secret

The Base32-encoded TOTP secret (as stored in LDAP).

=head4 user

The account label shown in the authenticator app.

=head4 issuer

The issuer name shown in the authenticator app. Defaults to the
C<totpissuer> config value (default C<Nisaba>).

    my $b64 = $pt->totpQRCodeBase64({
        secret => $totp_info->{totpSecret},
        user   => 'jdoe',
    });
    # Use in template: <img src="data:image/png;base64,<%= $b64 %>">

=cut

sub totpQRCodeBase64 {
	my $self = $_[0];
	my %args;
	if ( defined( $_[1] ) ) { %args = %{ $_[1] } }

	$self->errorblank;

	if ( !defined( $args{secret} ) || $args{secret} eq '' ) {
		$self->{error}       = 81;
		$self->{errorString} = 'No TOTP secret specified';
		$self->warn;
		return undef;
	}
	if ( !defined( $args{user} ) ) {
		$self->{error}       = 5;
		$self->{errorString} = 'No user name specified';
		$self->warn;
		return undef;
	}

	my $issuer    = $args{issuer} // $self->{ini}->{''}->{totpissuer};
	my $algorithm = uc( $args{algorithm} // 'SHA1' );
	my $digits    = $args{digits} // 6;
	my $period    = $args{period} // 30;

	my $gen = Authen::TOTP->new(
		base32secret => $args{secret},
		algorithm    => $algorithm,
		digits       => $digits,
		period       => $period
	);
	my $uri = $gen->generate_otp( user => $args{user}, issuer => $issuer );

	my $qrcode = Imager::QRCode->new(
		size          => 4,
		margin        => 3,
		level         => 'M',
		casesensitive => 1,
		lightcolor    => Imager::Color->new( 255, 255, 255 ),
		darkcolor     => Imager::Color->new( 0,   0,   0 ),
	);

	my $img = $qrcode->plot($uri);

	my $png_data;
	$img->write( data => \$png_data, type => 'png' );

	return encode_base64( $png_data, '' );
} ## end sub totpQRCodeBase64

1;

=head1 AUTHOR

Zane C. Bowers, C<< <vvelox at vvelox.net> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-nisaba at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=App::Nisaba>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc App::Nisaba


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=App::Nisaba>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/App::Nisaba>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/App::Nisaba>

=item * Search CPAN

L<http://search.cpan.org/dist/App::Nisaba/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 COPYRIGHT & LICENSE

Copyright 2010 Zane C. Bowers, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.


=cut

1;
