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

	$self->render( template => 'users/show', entry => $entry, username => $user );
} ## end sub show

sub edit {
	my $self = shift;
	my $user = $self->param('user');

	my $entry;
	eval { $entry = $self->pt->getUserEntry( { user => $user } ) };
	if ($@) {
		$self->flash( error => "Failed to fetch user '$user': $@" );
		return $self->redirect_to('users_index');
	}

	$self->render( template => 'users/edit', entry => $entry, username => $user );
} ## end sub edit

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
	} else {
		$self->flash( error => "Unknown action: $action" );
		return $self->redirect_to( 'users_edit', user => $user );
	}

	if ($error) {
		$self->flash( error => "Failed to update user '$user': $error" );
		return $self->redirect_to( 'users_edit', user => $user );
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

1;
