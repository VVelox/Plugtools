package App::Plugtools::Web::Controller::Groups;

use Mojo::Base 'Mojolicious::Controller';

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

	eval { $self->pt->addGroup( \%params ) };
	if ($@) {
		$self->flash( error => "Failed to add group: $@" );
		return $self->redirect_to('groups_add');
	}

	$self->flash( success => "Group '$params{group}' added successfully." );
	$self->redirect_to('groups_index');
} ## end sub create

sub clean {
	my $self = shift;

	eval { $self->pt->groupClean };
	if ($@) {
		$self->flash( error => "Group clean failed: $@" );
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
	if ($@) {
		$self->flash( error => "Failed to fetch group '$group': $@" );
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

sub edit {
	my $self  = shift;
	my $group = $self->param('group');

	my $groups;
	eval { $groups = $self->pt->getGroups };
	if ($@) {
		$self->flash( error => "Failed to fetch group '$group': $@" );
		return $self->redirect_to('groups_index');
	}

	my ($entry) = grep { ( $_->get_value('cn') // '' ) eq $group } @{$groups};
	unless ($entry) {
		$self->flash( error => "Group '$group' not found in LDAP." );
		return $self->redirect_to('groups_index');
	}

	$self->render( template => 'groups/edit', entry => $entry, groupname => $group );
} ## end sub edit

sub update {
	my $self  = shift;
	my $group = $self->param('group');
	my $gid   = $self->param('gid');

	eval { $self->pt->groupGIDchange( { group => $group, gid => $gid } ) };
	if ($@) {
		$self->flash( error => "Failed to update group '$group': $@" );
		return $self->redirect_to( 'groups_edit', group => $group );
	}

	$self->flash( success => "Group '$group' GID updated successfully." );
	$self->redirect_to( 'groups_show', group => $group );
} ## end sub update

sub delete {
	my $self  = shift;
	my $group = $self->param('group');

	eval { $self->pt->deleteGroup($group) };
	if ($@) {
		$self->flash( error => "Failed to delete group '$group': $@" );
		return $self->redirect_to( 'groups_show', group => $group );
	}

	$self->flash( success => "Group '$group' deleted successfully." );
	$self->redirect_to('groups_index');
} ## end sub delete

sub add_member {
	my $self  = shift;
	my $group = $self->param('group');
	my $user  = $self->param('user');

	eval { $self->pt->groupAddUser( { group => $group, user => $user } ) };
	if ($@) {
		$self->flash( error => "Failed to add '$user' to '$group': $@" );
		return $self->redirect_to( 'groups_show', group => $group );
	}

	$self->flash( success => "User '$user' added to group '$group'." );
	$self->redirect_to( 'groups_show', group => $group );
} ## end sub add_member

sub remove_member {
	my $self  = shift;
	my $group = $self->param('group');
	my $user  = $self->param('user');

	eval { $self->pt->groupRemoveUser( { group => $group, user => $user } ) };
	if ($@) {
		$self->flash( error => "Failed to remove '$user' from '$group': $@" );
		return $self->redirect_to( 'groups_show', group => $group );
	}

	$self->flash( success => "User '$user' removed from group '$group'." );
	$self->redirect_to( 'groups_show', group => $group );
} ## end sub remove_member

1;
