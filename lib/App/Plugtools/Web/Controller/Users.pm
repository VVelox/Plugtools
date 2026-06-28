package App::Plugtools::Web::Controller::Users;

use Mojo::Base 'Mojolicious::Controller';

sub index {
	my $self = shift;

	my $users;
	eval { $users = $self->pt->getUsers };
	if ($@) {
		$self->flash( error => "Failed to fetch users: $@" );
		$users = [];
	}

	my @sorted = sort { $a->get_value('uid') cmp $b->get_value('uid') } @{$users};
	$self->render( template => 'users/index', users => \@sorted );
} ## end sub index

sub add {
	my $self = shift;
	$self->render( template => 'users/add' );
}

sub create {
	my $self   = shift;
	my %params = map { $_ => $self->param($_) }
		qw(user uid group gid gecos shell home createHome chownHome chmodHome chmodValue);

	# Remove empty strings so App::Plugtools uses its defaults
	delete $params{$_} for grep { !defined $params{$_} || $params{$_} eq '' } keys %params;

	eval { $self->pt->addUser( \%params ) };
	if ($@) {
		$self->flash( error => "Failed to add user: $@" );
		return $self->redirect_to('users_add');
	}

	$self->flash( success => "User '$params{user}' added successfully." );
	$self->redirect_to('users_index');
} ## end sub create

sub show {
	my $self = shift;
	my $user = $self->param('user');

	my $entry;
	eval { $entry = $self->pt->getUserEntry( { user => $user } ) };
	if ($@) {
		$self->flash( error => "Failed to fetch user '$user': $@" );
		return $self->redirect_to('users_index');
	}

	my @shells;
	if ( open my $fh, '<', '/etc/shells' ) {
		while (<$fh>) {
			chomp;
			next if /^\s*#/ || /^\s*$/;
			push @shells, $_;
		}
		close $fh;
	}

	my ( @member_groups, @nonmember_groups );
	my $all_groups;
	eval { $all_groups = $self->pt->getGroups };
	if ( !$@ && $all_groups ) {
		for my $g ( sort { $a->get_value('cn') cmp $b->get_value('cn') } @{$all_groups} ) {
			my %members = map { $_ => 1 } $g->get_value('memberUid');
			if ( $members{$user} ) {
				push @member_groups, $g;
			} else {
				push @nonmember_groups, $g;
			}
		}
	}

	my $has_password = 0;
	eval { $has_password = $self->pt->userHasPassword( { user => $user } ) // 0 };

	my $lpk_schema = 0;
	eval { $lpk_schema = $self->pt->ldapPublicKeyAvailable // 0 };

	my $has_lpk = 0;
	if ($entry) {
		my %oc = map { lc($_) => 1 } $entry->get_value('objectClass');
		$has_lpk = $oc{ldappublickey} ? 1 : 0;
	}

	$self->render(
		template         => 'users/show',
		entry            => $entry,
		username         => $user,
		shells           => \@shells,
		member_groups    => \@member_groups,
		nonmember_groups => \@nonmember_groups,
		has_password     => $has_password,
		lpk_schema       => $lpk_schema,
		has_lpk          => $has_lpk,
	);
} ## end sub show

sub update {
	my $self   = shift;
	my $user   = $self->param('user');
	my $action = $self->param('action') // '';

	my $error;
	if ( $action eq 'gecos' ) {
		eval { $self->pt->userGECOSchange( { user => $user, gecos => $self->param('gecos') } ) };
		$error = $@;
	} elsif ( $action eq 'shell' ) {
		eval { $self->pt->userShellChange( { user => $user, shell => $self->param('shell') } ) };
		$error = $@;
	} elsif ( $action eq 'uid' ) {
		eval { $self->pt->userUIDchange( { user => $user, uid => $self->param('uid') } ) };
		$error = $@;
	} elsif ( $action eq 'gid' ) {
		eval { $self->pt->userGIDchange( { user => $user, gid => $self->param('gid') } ) };
		$error = $@;
	} elsif ( $action eq 'home' ) {
		eval { $self->pt->userHomeChange( { user => $user, home => $self->param('home') } ) };
		$error = $@;
	} elsif ( $action eq 'title' ) {
		eval { $self->pt->userTitleChange( { user => $user, title => $self->param('title') } ) };
		$error = $@;
	} elsif ( $action eq 'roomNumber' ) {
		eval { $self->pt->userRoomNumberChange( { user => $user, roomNumber => $self->param('roomNumber') } ) };
		$error = $@;
	} elsif ( $action eq 'employeeNumber' ) {
		eval { $self->pt->userEmployeeNumberChange( { user => $user, employeeNumber => $self->param('employeeNumber') } ) };
		$error = $@;
	} elsif ( $action eq 'employeeType' ) {
		eval { $self->pt->userEmployeeTypeChange( { user => $user, employeeType => $self->param('employeeType') } ) };
		$error = $@;
	} elsif ( $action eq 'mail_add' ) {
		eval { $self->pt->userMailAdd( { user => $user, mail => $self->param('mail') } ) };
		$error = $@;
	} elsif ( $action eq 'mail_remove' ) {
		eval { $self->pt->userMailRemove( { user => $user, mail => $self->param('mail') } ) };
		$error = $@;
	} elsif ( $action eq 'telephoneNumber_add' ) {
		eval { $self->pt->userTelephoneNumberAdd( { user => $user, telephoneNumber => $self->param('telephoneNumber') } ) };
		$error = $@;
	} elsif ( $action eq 'telephoneNumber_remove' ) {
		eval { $self->pt->userTelephoneNumberRemove( { user => $user, telephoneNumber => $self->param('telephoneNumber') } ) };
		$error = $@;
	} elsif ( $action eq 'mobile_add' ) {
		eval { $self->pt->userMobileAdd( { user => $user, mobile => $self->param('mobile') } ) };
		$error = $@;
	} elsif ( $action eq 'mobile_remove' ) {
		eval { $self->pt->userMobileRemove( { user => $user, mobile => $self->param('mobile') } ) };
		$error = $@;
	} elsif ( $action eq 'preferredLanguage_add' ) {
		eval { $self->pt->userPreferredLanguageAdd( { user => $user, preferredLanguage => $self->param('preferredLanguage') } ) };
		$error = $@;
	} elsif ( $action eq 'preferredLanguage_remove' ) {
		eval { $self->pt->userPreferredLanguageRemove( { user => $user, preferredLanguage => $self->param('preferredLanguage') } ) };
		$error = $@;
	} elsif ( $action eq 'labeledURI_add' ) {
		eval { $self->pt->userLabeledURIAdd( { user => $user, labeledURI => $self->param('labeledURI') } ) };
		$error = $@;
	} elsif ( $action eq 'labeledURI_remove' ) {
		eval { $self->pt->userLabeledURIRemove( { user => $user, labeledURI => $self->param('labeledURI') } ) };
		$error = $@;
	} elsif ( $action eq 'sn' ) {
		eval { $self->pt->userSNchange( { user => $user, sn => $self->param('sn') } ) };
		$error = $@;
	} elsif ( $action eq 'givenName' ) {
		eval { $self->pt->userGivenNameChange( { user => $user, givenName => $self->param('givenName') } ) };
		$error = $@;
	} elsif ( $action eq 'displayName' ) {
		eval { $self->pt->userDisplayNameChange( { user => $user, displayName => $self->param('displayName') } ) };
		$error = $@;
	} elsif ( $action eq 'homePostalAddress' ) {
		eval { $self->pt->userHomePostalAddressChange( { user => $user, homePostalAddress => $self->param('homePostalAddress') } ) };
		$error = $@;
	} elsif ( $action eq 'description_add' ) {
		eval { $self->pt->userDescriptionAdd( { user => $user, description => $self->param('description') } ) };
		$error = $@;
	} elsif ( $action eq 'description_remove' ) {
		eval { $self->pt->userDescriptionRemove( { user => $user, description => $self->param('description') } ) };
		$error = $@;
	} elsif ( $action eq 'postalAddress_add' ) {
		eval { $self->pt->userPostalAddressAdd( { user => $user, postalAddress => $self->param('postalAddress') } ) };
		$error = $@;
	} elsif ( $action eq 'postalAddress_remove' ) {
		eval { $self->pt->userPostalAddressRemove( { user => $user, postalAddress => $self->param('postalAddress') } ) };
		$error = $@;
	} elsif ( $action eq 'cn_add' ) {
		eval { $self->pt->userCNadd( { user => $user, cn => $self->param('cn') } ) };
		$error = $@;
	} elsif ( $action eq 'cn_remove' ) {
		eval { $self->pt->userCNremove( { user => $user, cn => $self->param('cn') } ) };
		$error = $@;
	} elsif ( $action eq 'sshkey_add' ) {
		my $key = $self->param('key') // '';
		$key =~ s/[\r\n]+$//;    # strip trailing newline that textareas append
		eval { $self->pt->userSSHPublicKeyAdd( { user => $user, key => $key } ) };
		$error = $@;
	} elsif ( $action eq 'sshkey_remove' ) {
		eval { $self->pt->userSSHPublicKeyRemove( { user => $user, key => $self->param('key') } ) };
		$error = $@;
	} else {
		$self->flash( error => "Unknown action: $action" );
		return $self->redirect_to( 'users_show', user => $user );
	}

	if ($error) {
		$self->flash( error => "Failed to update user '$user': $error" );
		return $self->redirect_to( 'users_show', user => $user );
	}

	$self->flash( success => "User '$user' updated successfully." );
	$self->redirect_to( 'users_show', user => $user );
} ## end sub update

sub delete {
	my $self        = shift;
	my $user        = $self->param('user');
	my $removeHome  = $self->param('removeHome')  // 0;
	my $removeGroup = $self->param('removeGroup') // 1;

	eval { $self->pt->deleteUser( { user => $user, removeHome => $removeHome, removeGroup => $removeGroup } ); };
	if ($@) {
		$self->flash( error => "Failed to delete user '$user': $@" );
		return $self->redirect_to( 'users_show', user => $user );
	}

	$self->flash( success => "User '$user' deleted successfully." );
	$self->redirect_to('users_index');
} ## end sub delete

sub inetorgperson {
	my $self = shift;
	my $user = $self->param('user');

	eval { $self->pt->userConvertToInetOrgPerson( { user => $user } ) };
	if ($@) {
		$self->flash( error => "Failed to convert '$user' to inetOrgPerson: $@" );
		return $self->redirect_to( 'users_show', user => $user );
	}

	$self->flash( success => "User '$user' converted to inetOrgPerson." );
	$self->redirect_to( 'users_show', user => $user );
} ## end sub inetorgperson

sub lpk {
	my $self = shift;
	my $user = $self->param('user');

	eval { $self->pt->userConvertToLdapPublicKey( { user => $user } ) };
	if ($@) {
		$self->flash( error => "Failed to add ldapPublicKey objectClass to '$user': $@" );
		return $self->redirect_to( 'users_show', user => $user );
	}

	$self->flash( success => "SSH public key support enabled for '$user'." );
	$self->redirect_to( 'users_show', user => $user );
} ## end sub lpk

sub password {
	my $self = shift;
	my $user = $self->param('user');
	my $pass = $self->param('pass');

	eval { $self->pt->userSetPass( { user => $user, pass => $pass } ) };
	if ($@) {
		$self->flash( error => "Failed to set password for '$user': $@" );
		return $self->redirect_to( 'users_show', user => $user );
	}

	$self->flash( success => "Password updated for '$user'." );
	$self->redirect_to( 'users_show', user => $user );
} ## end sub password

sub remove_password {
	my $self = shift;
	my $user = $self->param('user');

	eval { $self->pt->userRemovePassword( { user => $user } ) };
	if ($@) {
		$self->flash( error => "Failed to remove password for '$user': $@" );
		return $self->redirect_to( 'users_show', user => $user );
	}

	$self->flash( success => "Password removed for '$user'." );
	$self->redirect_to( 'users_show', user => $user );
} ## end sub remove_password

sub add_to_group {
	my $self   = shift;
	my $user   = $self->param('user');
	my @groups = @{ $self->every_param('group') };

	my ( @added, @failed );
	for my $group (@groups) {
		eval { $self->pt->groupAddUser( { user => $user, group => $group } ) };
		if ($@) {
			push @failed, $group;
		} else {
			push @added, $group;
		}
	}

	if (@failed) {
		$self->flash( error => "Failed to add '$user' to: " . join( ', ', @failed ) );
	}
	if (@added) {
		$self->flash( success => "Added '$user' to: " . join( ', ', @added ) );
	}
	$self->redirect_to( 'users_show', user => $user );
} ## end sub add_to_group

sub remove_from_group {
	my $self  = shift;
	my $user  = $self->param('user');
	my $group = $self->param('group');

	eval { $self->pt->groupRemoveUser( { user => $user, group => $group } ) };
	if ($@) {
		$self->flash( error => "Failed to remove '$user' from group '$group': $@" );
		return $self->redirect_to( 'users_show', user => $user );
	}

	$self->flash( success => "Removed '$user' from group '$group'." );
	$self->redirect_to( 'users_show', user => $user );
} ## end sub remove_from_group

1;
