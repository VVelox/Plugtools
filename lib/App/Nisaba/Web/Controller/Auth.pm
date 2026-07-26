package App::Nisaba::Web::Controller::Auth;

use Mojo::Base 'Mojolicious::Controller', -signatures;
use experimental 'signatures';    # redundant at runtime; here so perlcritic recognises signatures
use Net::LDAP::Util      qw(escape_filter_value);
use App::Nisaba::WebUtil ();

# --------------------------------------------------------------------------- #
# Auth middleware — used as an under() bridge
# --------------------------------------------------------------------------- #

sub require_login ($self) {
	return 1 if $self->session('admin_user');
	$self->redirect_to('admin_login');
	return undef;
}

# --------------------------------------------------------------------------- #
# Login
# --------------------------------------------------------------------------- #

sub login_form ($self) {
	$self->render( template => 'admin/login' );
}

# Where the shared login flows (App::Nisaba::WebUtil) keep this app's session
# state and where each step navigates next.
sub _login_flow_callbacks ($self) {
	return (
		set_totp_pending => sub ( $c, $user ) { $c->session( admin_totp_pending_user => $user ) },
		set_logged_in    => sub ( $c, $user ) {
			delete $c->session->{admin_totp_pending_user};
			$c->session( admin_user => $user );
		},
		goto_totp_challenge => sub ($c) { $c->redirect_to('admin_totp_challenge') },
		goto_logged_in      => sub ($c) { $c->redirect_to('users_index') },
	);
} ## end sub _login_flow_callbacks

sub login ($self) {
	App::Nisaba::WebUtil::handle_password_login(
		$self,
		$self->_login_flow_callbacks,
		render_block   => { template => 'admin/login' },
		redirect_login => sub ($c) { $c->redirect_to('admin_login') },
		# Verify user is a member of the admin group
		verify_extra => sub ( $c, $user ) {
			return 1 if $c->_is_admin($user);
			$c->flash( error => 'You are not authorised to access the admin portal.' );
			$c->redirect_to('admin_login');
			return 0;
		},
	);
} ## end sub login

# --------------------------------------------------------------------------- #
# Passkey login
# --------------------------------------------------------------------------- #

sub passkey_login_start ($self) {
	App::Nisaba::WebUtil::handle_passkey_login_start( $self, challenge_session_key => 'admin_passkey_login_challenge' );
}

sub passkey_login_finish ($self) {
	App::Nisaba::WebUtil::handle_passkey_login_finish(
		$self,
		$self->_login_flow_callbacks,
		challenge_session_key => 'admin_passkey_login_challenge',
		# Verify user is a member of the admin group
		verify_extra => sub ( $c, $user ) {
			return 1 if $c->_is_admin($user);
			$c->render(
				json   => { error => 'You are not authorised to access the admin portal.' },
				status => 403
			);
			return 0;
		},
	);
} ## end sub passkey_login_finish

# --------------------------------------------------------------------------- #
# TOTP challenge
# --------------------------------------------------------------------------- #

sub totp_challenge_form ($self) {
	unless ( $self->session('admin_totp_pending_user') ) {
		return $self->redirect_to('admin_login');
	}
	$self->render( template => 'admin/totp_challenge' );
}

sub totp_challenge ($self) {
	my $user = $self->session('admin_totp_pending_user');
	unless ($user) {
		return $self->redirect_to('admin_login');
	}

	App::Nisaba::WebUtil::handle_totp_challenge(
		$self,
		$self->_login_flow_callbacks,
		pending_user            => $user,
		render_block            => { template => 'admin/totp_challenge' },
		redirect_totp_challenge => sub ($c) { $c->redirect_to('admin_totp_challenge') },
	);
} ## end sub totp_challenge

# --------------------------------------------------------------------------- #
# Logout
# --------------------------------------------------------------------------- #

sub logout ($self) {
	$self->session( expires => 1 );
	$self->redirect_to('admin_login');
}

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

# Check whether $user is a member of the configured admin group.
# Membership means the user is listed in memberUid OR the user's primary
# gidNumber matches the group's gidNumber.
sub _is_admin ( $self, $user ) {
	my $pt        = $self->pt;
	my $admin_grp = $pt->{ini}->{''}->{adminGroup};
	my $ldap      = $pt->connect();
	return 0 unless $ldap;

	# Find the admin group in LDAP
	my $grp_mesg = $ldap->search(
		base   => $pt->{ini}->{''}->{groupbase},
		filter => '(&(objectClass=posixGroup)(cn=' . escape_filter_value($admin_grp) . '))',
	);
	my $grp_entry = $grp_mesg->pop_entry;
	return 0 unless $grp_entry;

	# Explicit memberUid check
	my @members = $grp_entry->get_value('memberUid');
	for my $m (@members) {
		return 1 if $m eq $user;
	}

	# Primary-group check: user's gidNumber == group's gidNumber
	my $grp_gid = $grp_entry->get_value('gidNumber');
	if ( defined $grp_gid ) {
		my $usr_mesg = $ldap->search(
			base   => $pt->{ini}->{''}->{userbase},
			filter => '(uid=' . escape_filter_value($user) . ')',
			attrs  => ['gidNumber'],
		);
		my $usr_entry = $usr_mesg->pop_entry;
		if ( $usr_entry && ( $usr_entry->get_value('gidNumber') // '' ) eq $grp_gid ) {
			return 1;
		}
	} ## end if ( defined $grp_gid )

	return 0;
} ## end sub _is_admin

1;
