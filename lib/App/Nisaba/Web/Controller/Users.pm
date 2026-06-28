package App::Nisaba::Web::Controller::Users;

use Mojo::Base 'Mojolicious::Controller';

# Invoke a coderef that calls a pt method.  Returns an error string if the
# call died OR if the pt helper recorded an Error::Helper error, empty string
# on success.  This covers both die-based and return-undef-based failures.
sub _pt_call {
	my ( $self, $code ) = @_;
	eval { $code->() };
	return $@ if $@;
	if ( $self->pt->error ) {
		return $self->pt->errorString || ( 'Error code ' . $self->pt->error );
	}
	return '';
} ## end sub _pt_call

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

	# Remove empty strings so App::Nisaba uses its defaults
	delete $params{$_} for grep { !defined $params{$_} || $params{$_} eq '' } keys %params;

	my $error = $self->_pt_call( sub { $self->pt->addUser( \%params ) } );
	if ($error) {
		$self->flash( error => "Failed to add user: $error" );
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
	if ( $@ || $self->pt->error ) {
		my $msg = $@ || $self->pt->errorString || 'Unknown error';
		$self->flash( error => "Failed to fetch user '$user': $msg" );
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
		$error = $self->_pt_call( sub { $self->pt->userGECOSchange( { user => $user, gecos => $self->param('gecos') } ) } );
	} elsif ( $action eq 'shell' ) {
		$error = $self->_pt_call( sub { $self->pt->userShellChange( { user => $user, shell => $self->param('shell') } ) } );
	} elsif ( $action eq 'uid' ) {
		$error = $self->_pt_call( sub { $self->pt->userUIDchange( { user => $user, uid => $self->param('uid') } ) } );
	} elsif ( $action eq 'gid' ) {
		$error = $self->_pt_call( sub { $self->pt->userGIDchange( { user => $user, gid => $self->param('gid') } ) } );
	} elsif ( $action eq 'home' ) {
		$error = $self->_pt_call( sub { $self->pt->userHomeChange( { user => $user, home => $self->param('home') } ) } );
	} elsif ( $action eq 'title' ) {
		$error = $self->_pt_call( sub { $self->pt->userTitleChange( { user => $user, title => $self->param('title') } ) } );
	} elsif ( $action eq 'roomNumber' ) {
		$error = $self->_pt_call( sub { $self->pt->userRoomNumberChange( { user => $user, roomNumber => $self->param('roomNumber') } ) } );
	} elsif ( $action eq 'employeeNumber' ) {
		$error = $self->_pt_call( sub { $self->pt->userEmployeeNumberChange( { user => $user, employeeNumber => $self->param('employeeNumber') } ) } );
	} elsif ( $action eq 'employeeType' ) {
		$error = $self->_pt_call( sub { $self->pt->userEmployeeTypeChange( { user => $user, employeeType => $self->param('employeeType') } ) } );
	} elsif ( $action eq 'mail_add' ) {
		$error = $self->_pt_call( sub { $self->pt->userMailAdd( { user => $user, mail => $self->param('mail') } ) } );
	} elsif ( $action eq 'mail_remove' ) {
		$error = $self->_pt_call( sub { $self->pt->userMailRemove( { user => $user, mail => $self->param('mail') } ) } );
	} elsif ( $action eq 'telephoneNumber_add' ) {
		$error = $self->_pt_call( sub { $self->pt->userTelephoneNumberAdd( { user => $user, telephoneNumber => $self->param('telephoneNumber') } ) } );
	} elsif ( $action eq 'telephoneNumber_remove' ) {
		$error = $self->_pt_call( sub { $self->pt->userTelephoneNumberRemove( { user => $user, telephoneNumber => $self->param('telephoneNumber') } ) } );
	} elsif ( $action eq 'mobile_add' ) {
		$error = $self->_pt_call( sub { $self->pt->userMobileAdd( { user => $user, mobile => $self->param('mobile') } ) } );
	} elsif ( $action eq 'mobile_remove' ) {
		$error = $self->_pt_call( sub { $self->pt->userMobileRemove( { user => $user, mobile => $self->param('mobile') } ) } );
	} elsif ( $action eq 'preferredLanguage_add' ) {
		$error = $self->_pt_call( sub { $self->pt->userPreferredLanguageAdd( { user => $user, preferredLanguage => $self->param('preferredLanguage') } ) } );
	} elsif ( $action eq 'preferredLanguage_remove' ) {
		$error = $self->_pt_call( sub { $self->pt->userPreferredLanguageRemove( { user => $user, preferredLanguage => $self->param('preferredLanguage') } ) } );
	} elsif ( $action eq 'labeledURI_add' ) {
		$error = $self->_pt_call( sub { $self->pt->userLabeledURIAdd( { user => $user, labeledURI => $self->param('labeledURI') } ) } );
	} elsif ( $action eq 'labeledURI_remove' ) {
		$error = $self->_pt_call( sub { $self->pt->userLabeledURIRemove( { user => $user, labeledURI => $self->param('labeledURI') } ) } );
	} elsif ( $action eq 'sn' ) {
		$error = $self->_pt_call( sub { $self->pt->userSNchange( { user => $user, sn => $self->param('sn') } ) } );
	} elsif ( $action eq 'givenName' ) {
		$error = $self->_pt_call( sub { $self->pt->userGivenNameChange( { user => $user, givenName => $self->param('givenName') } ) } );
	} elsif ( $action eq 'displayName' ) {
		$error = $self->_pt_call( sub { $self->pt->userDisplayNameChange( { user => $user, displayName => $self->param('displayName') } ) } );
	} elsif ( $action eq 'homePostalAddress' ) {
		$error = $self->_pt_call( sub { $self->pt->userHomePostalAddressChange( { user => $user, homePostalAddress => $self->param('homePostalAddress') } ) } );
	} elsif ( $action eq 'description_add' ) {
		$error = $self->_pt_call( sub { $self->pt->userDescriptionAdd( { user => $user, description => $self->param('description') } ) } );
	} elsif ( $action eq 'description_remove' ) {
		$error = $self->_pt_call( sub { $self->pt->userDescriptionRemove( { user => $user, description => $self->param('description') } ) } );
	} elsif ( $action eq 'postalAddress_add' ) {
		$error = $self->_pt_call( sub { $self->pt->userPostalAddressAdd( { user => $user, postalAddress => $self->param('postalAddress') } ) } );
	} elsif ( $action eq 'postalAddress_remove' ) {
		$error = $self->_pt_call( sub { $self->pt->userPostalAddressRemove( { user => $user, postalAddress => $self->param('postalAddress') } ) } );
	} elsif ( $action eq 'cn_add' ) {
		$error = $self->_pt_call( sub { $self->pt->userCNadd( { user => $user, cn => $self->param('cn') } ) } );
	} elsif ( $action eq 'cn_remove' ) {
		$error = $self->_pt_call( sub { $self->pt->userCNremove( { user => $user, cn => $self->param('cn') } ) } );
	} elsif ( $action eq 'sshkey_add' ) {
		my $key = $self->param('key') // '';
		$key =~ s/[\r\n]+$//;    # strip trailing newline that textareas append
		$error = $self->_pt_call( sub { $self->pt->userSSHPublicKeyAdd( { user => $user, key => $key } ) } );
	} elsif ( $action eq 'sshkey_remove' ) {
		$error = $self->_pt_call( sub { $self->pt->userSSHPublicKeyRemove( { user => $user, key => $self->param('key') } ) } );
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

	my $error = $self->_pt_call( sub { $self->pt->deleteUser( { user => $user, removeHome => $removeHome, removeGroup => $removeGroup } ) } );
	if ($error) {
		$self->flash( error => "Failed to delete user '$user': $error" );
		return $self->redirect_to( 'users_show', user => $user );
	}

	$self->flash( success => "User '$user' deleted successfully." );
	$self->redirect_to('users_index');
} ## end sub delete

sub inetorgperson {
	my $self = shift;
	my $user = $self->param('user');

	my $error = $self->_pt_call( sub { $self->pt->userConvertToInetOrgPerson( { user => $user } ) } );
	if ($error) {
		$self->flash( error => "Failed to convert '$user' to inetOrgPerson: $error" );
		return $self->redirect_to( 'users_show', user => $user );
	}

	$self->flash( success => "User '$user' converted to inetOrgPerson." );
	$self->redirect_to( 'users_show', user => $user );
} ## end sub inetorgperson

sub lpk {
	my $self = shift;
	my $user = $self->param('user');

	my $error = $self->_pt_call( sub { $self->pt->userConvertToLdapPublicKey( { user => $user } ) } );
	if ($error) {
		$self->flash( error => "Failed to add ldapPublicKey objectClass to '$user': $error" );
		return $self->redirect_to( 'users_show', user => $user );
	}

	$self->flash( success => "SSH public key support enabled for '$user'." );
	$self->redirect_to( 'users_show', user => $user );
} ## end sub lpk

sub password {
	my $self = shift;
	my $user = $self->param('user');

	my $error = $self->_pt_call( sub { $self->pt->userSetPass( { user => $user, pass => $self->param('pass') } ) } );
	if ($error) {
		$self->flash( error => "Failed to set password for '$user': $error" );
		return $self->redirect_to( 'users_show', user => $user );
	}

	$self->flash( success => "Password updated for '$user'." );
	$self->redirect_to( 'users_show', user => $user );
} ## end sub password

sub remove_password {
	my $self = shift;
	my $user = $self->param('user');

	my $error = $self->_pt_call( sub { $self->pt->userRemovePassword( { user => $user } ) } );
	if ($error) {
		$self->flash( error => "Failed to remove password for '$user': $error" );
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
		my $err = $self->_pt_call( sub { $self->pt->groupAddUser( { user => $user, group => $group } ) } );
		if ($err) {
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

	my $error = $self->_pt_call( sub { $self->pt->groupRemoveUser( { user => $user, group => $group } ) } );
	if ($error) {
		$self->flash( error => "Failed to remove '$user' from group '$group': $error" );
		return $self->redirect_to( 'users_show', user => $user );
	}

	$self->flash( success => "Removed '$user' from group '$group'." );
	$self->redirect_to( 'users_show', user => $user );
} ## end sub remove_from_group

1;
