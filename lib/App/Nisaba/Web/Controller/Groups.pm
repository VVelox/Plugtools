package App::Nisaba::Web::Controller::Groups;

use Mojo::Base 'Mojolicious::Controller';

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

	my $groups;
	eval { $groups = $self->pt->getGroups };
	if ($@) {
		$self->flash( error => "Failed to fetch groups: $@" );
		$groups = [];
	}

	my @sorted = sort { $a->get_value('cn') cmp $b->get_value('cn') } @{$groups};
	$self->render( template => 'groups/index', groups => \@sorted );
} ## end sub index

sub add {
	my $self = shift;
	$self->render( template => 'groups/add' );
}

sub create {
	my $self   = shift;
	my %params = map { $_ => $self->param($_) } qw(group gid);
	delete $params{$_} for grep { !defined $params{$_} || $params{$_} eq '' } keys %params;

	my $error = $self->_pt_call( sub { $self->pt->addGroup( \%params ) } );
	if ($error) {
		$self->flash( error => "Failed to add group: $error" );
		return $self->redirect_to('groups_add');
	}

	$self->flash( success => "Group '$params{group}' added successfully." );
	$self->redirect_to('groups_index');
} ## end sub create

sub clean {
	my $self = shift;

	my $error = $self->_pt_call( sub { $self->pt->groupClean } );
	if ($error) {
		$self->flash( error => "Group clean failed: $error" );
		return $self->redirect_to('groups_index');
	}

	$self->flash( success => 'Group clean completed: stale members removed.' );
	$self->redirect_to('groups_index');
} ## end sub clean

sub show {
	my $self  = shift;
	my $group = $self->param('group');

	# Fetch the LDAP entry for this group
	my $groups;
	eval { $groups = $self->pt->getGroups };
	if ( $@ || $self->pt->error ) {
		my $msg = $@ || $self->pt->errorString || 'Unknown error';
		$self->flash( error => "Failed to fetch group '$group': $msg" );
		return $self->redirect_to('groups_index');
	}

	my ($entry) = grep { ( $_->get_value('cn') // '' ) eq $group } @{$groups};
	unless ($entry) {
		$self->flash( error => "Group '$group' not found in LDAP." );
		return $self->redirect_to('groups_index');
	}

	# Fetch all users for the "add member" drop-down
	my $all_users;
	eval { $all_users = $self->pt->getUsers };
	$all_users //= [];
	my @member_uids = $entry->get_value('memberUid');
	my %is_member   = map       { $_ => 1 } @member_uids;
	my @non_members = sort grep { !$is_member{ $_->get_value('uid') } } @{$all_users};

	$self->render(
		template    => 'groups/show',
		entry       => $entry,
		groupname   => $group,
		non_members => \@non_members,
	);
} ## end sub show

sub update {
	my $self   = shift;
	my $group  = $self->param('group');
	my $action = $self->param('action') // 'gid';

	my $error;
	if ( $action eq 'gid' ) {
		$error = $self->_pt_call( sub { $self->pt->groupGIDchange( { group => $group, gid => $self->param('gid') } ) } );
	} elsif ( $action eq 'description' ) {
		$error = $self->_pt_call( sub { $self->pt->groupDescriptionChange( { group => $group, description => $self->param('description') } ) } );
	} else {
		$self->flash( error => "Unknown action: $action" );
		return $self->redirect_to( 'groups_show', group => $group );
	}

	if ($error) {
		$self->flash( error => "Failed to update group '$group': $error" );
		return $self->redirect_to( 'groups_show', group => $group );
	}

	$self->flash( success => "Group '$group' updated successfully." );
	$self->redirect_to( 'groups_show', group => $group );
} ## end sub update

sub delete {
	my $self  = shift;
	my $group = $self->param('group');

	my $error = $self->_pt_call( sub { $self->pt->deleteGroup($group) } );
	if ($error) {
		$self->flash( error => "Failed to delete group '$group': $error" );
		return $self->redirect_to( 'groups_show', group => $group );
	}

	$self->flash( success => "Group '$group' deleted successfully." );
	$self->redirect_to('groups_index');
} ## end sub delete

sub add_member {
	my $self  = shift;
	my $group = $self->param('group');
	my $user  = $self->param('user');

	my $error = $self->_pt_call( sub { $self->pt->groupAddUser( { group => $group, user => $user } ) } );
	if ($error) {
		$self->flash( error => "Failed to add '$user' to '$group': $error" );
		return $self->redirect_to( 'groups_show', group => $group );
	}

	$self->flash( success => "User '$user' added to group '$group'." );
	$self->redirect_to( 'groups_show', group => $group );
} ## end sub add_member

sub remove_member {
	my $self  = shift;
	my $group = $self->param('group');
	my $user  = $self->param('user');

	my $error = $self->_pt_call( sub { $self->pt->groupRemoveUser( { group => $group, user => $user } ) } );
	if ($error) {
		$self->flash( error => "Failed to remove '$user' from '$group': $error" );
		return $self->redirect_to( 'groups_show', group => $group );
	}

	$self->flash( success => "User '$user' removed from group '$group'." );
	$self->redirect_to( 'groups_show', group => $group );
} ## end sub remove_member

1;
