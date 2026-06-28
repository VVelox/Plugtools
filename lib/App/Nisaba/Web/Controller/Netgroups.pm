package App::Nisaba::Web::Controller::Netgroups;

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

# Returns 1 if netgroupbase is configured; otherwise flashes an error,
# redirects to the groups index, and returns 0.
sub _check_configured {
	my $self = shift;
	return 1 if $self->pt->netgroupbaseConfigured;
	$self->flash( error => 'Netgroup support is not configured (netgroupbase is not set).' );
	$self->redirect_to('groups_index');
	return 0;
} ## end sub _check_configured

sub index {
	my $self = shift;

	return unless $self->_check_configured;

	my $netgroups;
	eval { $netgroups = $self->pt->getNetgroups };
	if ( $@ || $self->pt->error ) {
		my $msg = $@ || $self->pt->errorString || 'Unknown error';
		$self->flash( error => "Failed to fetch netgroups: $msg" );
		$netgroups = [];
	}

	my @sorted = sort { $a->get_value('cn') cmp $b->get_value('cn') } @{$netgroups};
	$self->render( template => 'netgroups/index', netgroups => \@sorted );
} ## end sub index

sub add {
	my $self = shift;
	return unless $self->_check_configured;
	$self->render( template => 'netgroups/add' );
}

sub create {
	my $self = shift;

	return unless $self->_check_configured;

	my $group       = $self->param('group');
	my $description = $self->param('description');
	my @triples     = grep { defined($_) && $_ ne '' } $self->every_param('triple')->@*;
	my @members     = grep { defined($_) && $_ ne '' } $self->every_param('member')->@*;

	# Triples may be entered one per line in a textarea — split on newlines too
	@triples = map { split /\r?\n/, $_ } @triples;
	@triples = grep { $_ ne '' } @triples;

	@members = map { split /\r?\n/, $_ } @members;
	@members = grep { $_ ne '' } @members;

	my %args = ( group => $group );
	$args{triples}     = \@triples    if @triples;
	$args{members}     = \@members    if @members;
	$args{description} = $description if defined($description) && $description ne '';

	my $error = $self->_pt_call( sub { $self->pt->addNetgroup( \%args ) } );
	if ($error) {
		$self->flash( error => "Failed to add netgroup: $error" );
		return $self->redirect_to('netgroups_add');
	}

	$self->flash( success => "Netgroup '$group' added successfully." );
	$self->redirect_to('netgroups_index');
} ## end sub create

sub show {
	my $self  = shift;
	my $group = $self->param('group');

	return unless $self->_check_configured;

	my $entry;
	eval { $entry = $self->pt->getNetgroupEntry( { group => $group } ) };
	if ( $@ || $self->pt->error || !defined($entry) ) {
		$self->flash( error => "Netgroup '$group' not found." );
		return $self->redirect_to('netgroups_index');
	}

	# Fetch all netgroups for the member candidate list
	my $all_netgroups;
	eval { $all_netgroups = $self->pt->getNetgroups };
	$all_netgroups //= [];

	my @current_members = $entry->get_value('memberNisNetgroup');
	my %is_member       = map { $_ => 1 } @current_members;

	# Filter out self and already-members from candidate list
	my @candidate_groups = sort { $a->get_value('cn') cmp $b->get_value('cn') }
		grep { my $cn = $_->get_value('cn'); $cn ne $group && !$is_member{$cn} } @{$all_netgroups};

	$self->render(
		template      => 'netgroups/show',
		entry         => $entry,
		groupname     => $group,
		all_netgroups => \@candidate_groups,
	);
} ## end sub show

sub update {
	my $self   = shift;
	my $group  = $self->param('group');
	my $action = $self->param('action') // '';

	return unless $self->_check_configured;

	my $error;
	if ( $action eq 'description' ) {
		$error = $self->_pt_call( sub { $self->pt->netgroupDescriptionChange( { group => $group, description => $self->param('description') } ) } );
	} elsif ( $action eq 'triple_add' ) {
		$error = $self->_pt_call( sub { $self->pt->netgroupTripleAdd( { group => $group, triple => $self->param('triple') } ) } );
	} elsif ( $action eq 'triple_remove' ) {
		$error = $self->_pt_call( sub { $self->pt->netgroupTripleRemove( { group => $group, triple => $self->param('triple') } ) } );
	} elsif ( $action eq 'member_add' ) {
		$error = $self->_pt_call( sub { $self->pt->netgroupMemberAdd( { group => $group, member => $self->param('member') } ) } );
	} elsif ( $action eq 'member_remove' ) {
		$error = $self->_pt_call( sub { $self->pt->netgroupMemberRemove( { group => $group, member => $self->param('member') } ) } );
	} else {
		$self->flash( error => "Unknown action: $action" );
		return $self->redirect_to( 'netgroups_show', group => $group );
	}

	if ($error) {
		$self->flash( error => "Failed to update netgroup '$group': $error" );
		return $self->redirect_to( 'netgroups_show', group => $group );
	}

	$self->flash( success => "Netgroup '$group' updated successfully." );
	$self->redirect_to( 'netgroups_show', group => $group );
} ## end sub update

sub delete {
	my $self  = shift;
	my $group = $self->param('group');

	return unless $self->_check_configured;

	my $error = $self->_pt_call( sub { $self->pt->deleteNetgroup( { group => $group } ) } );
	if ($error) {
		$self->flash( error => "Failed to delete netgroup '$group': $error" );
		return $self->redirect_to( 'netgroups_show', group => $group );
	}

	$self->flash( success => "Netgroup '$group' deleted successfully." );
	$self->redirect_to('netgroups_index');
} ## end sub delete

1;
