package App::Nisaba::Web::Controller::Auth;

use Mojo::Base 'Mojolicious::Controller', -signatures;
use experimental 'signatures';    # redundant at runtime; here so perlcritic recognises signatures
use Mojo::Util      qw(b64_encode);
use Net::LDAP::Util qw(escape_filter_value);

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

sub login ($self) {
	my $user = $self->param('user') // '';
	my $pass = $self->param('pass') // '';

	return unless $self->rate_guard( 'login', user => $user, render => { template => 'admin/login' } );

	my $err = $self->pt_call( sub { $self->pt->userVerifyPassword( { user => $user, password => $pass } ) } );
	if ($err) {
		$self->rate_fail( 'login', user => $user );
		$self->flash( error => 'Invalid username or password.' );
		return $self->redirect_to('admin_login');
	}
	$self->rate_reset( 'login', user => $user );

	# Verify user is a member of the admin group
	unless ( $self->_is_admin($user) ) {
		$self->flash( error => 'You are not authorised to access the admin portal.' );
		return $self->redirect_to('admin_login');
	}

	# Check whether TOTP is active for this user
	my $info;
	$self->pt_call( sub { $info = $self->pt->userSelfInfo( { user => $user } ) } );
	if ( $info && ( $info->{totpStatus} // '' ) eq 'active' ) {
		$self->session( admin_totp_pending_user => $user );
		return $self->redirect_to('admin_totp_challenge');
	}

	$self->session( admin_user => $user );
	$self->redirect_to('users_index');
} ## end sub login

# --------------------------------------------------------------------------- #
# Passkey login
# --------------------------------------------------------------------------- #

sub passkey_login_start ($self) {
	my $challenge_bytes = '';
	open my $fh, '<:raw', '/dev/urandom' or do {
		return $self->render( json => { error => 'Could not generate challenge' }, status => 500 );
	};
	read $fh, $challenge_bytes, 32;
	close $fh;

	my $challenge_b64 = b64_encode( $challenge_bytes, '' );
	$challenge_b64 =~ tr|+/|-_|;
	$challenge_b64 =~ s/=+$//;
	$self->session( admin_passkey_login_challenge => $challenge_b64 );

	my $rp_id = $self->pt->{ini}->{''}->{passkeyRpId}             || $self->req->url->to_abs->host;
	my $uv    = $self->pt->{ini}->{''}->{passkeyUserVerification} || 'preferred';

	$self->render(
		json => {
			challenge        => $challenge_b64,
			rpId             => $rp_id,
			userVerification => $uv,
			allowCredentials => [],
			timeout          => 60000,
		}
	);
} ## end sub passkey_login_start

sub passkey_login_finish ($self) {
	return unless $self->rate_guard( 'passkey', render => { json => 1 } );

	my $challenge_b64 = $self->session('admin_passkey_login_challenge');
	unless ($challenge_b64) {
		return $self->render( json => { error => 'No login in progress' }, status => 400 );
	}
	delete $self->session->{admin_passkey_login_challenge};

	my $body = $self->req->json;
	unless ( $body && ref $body->{response} eq 'HASH' ) {
		return $self->render( json => { error => 'Invalid request body' }, status => 400 );
	}

	my $credential_id = $body->{id} // '';
	unless ($credential_id) {
		return $self->render( json => { error => 'Missing credential ID' }, status => 400 );
	}

	# Look up which user owns this credential
	my $found;
	my $find_err = $self->pt_call(
		sub { $found = $self->pt->userPasskeyFindByCredentialId( { credentialId => $credential_id } ) } );
	if ( $find_err || !$found ) {
		return $self->render( json => { error => 'Unknown passkey' }, status => 401 );
	}

	my $user = $found->{user};
	my $cred = $found->{credential};

	# Verify user is a member of the admin group
	unless ( $self->_is_admin($user) ) {
		return $self->render(
			json   => { error => 'You are not authorised to access the admin portal.' },
			status => 403
		);
	}

	my $url    = $self->req->url->to_abs;
	my $rp_id  = $self->pt->{ini}->{''}->{passkeyRpId}             || $url->host;
	my $uv     = $self->pt->{ini}->{''}->{passkeyUserVerification} || 'preferred';
	my $origin = $url->scheme . '://' . $url->host;
	my $port   = $url->port;
	$origin .= ":$port"
		if $port
		&& !( ( $url->scheme eq 'https' && $port == 443 ) || ( $url->scheme eq 'http' && $port == 80 ) );

	my $wa = eval { require Authen::WebAuthn; Authen::WebAuthn->new( rp_id => $rp_id, origin => $origin ) };
	unless ($wa) {
		return $self->render(
			json   => { error => 'WebAuthn not available on this server (Authen::WebAuthn not installed)' },
			status => 501,
		);
	}

	my $result = eval {
		$wa->validate_assertion(
			challenge_b64          => $challenge_b64,
			credential_pubkey_b64  => $cred->{cosePublicKey},
			stored_sign_count      => $cred->{signCount},
			requested_uv           => $uv,
			client_data_json_b64   => $body->{response}{clientDataJSON},
			authenticator_data_b64 => $body->{response}{authenticatorData},
			signature_b64          => $body->{response}{signature},
			user_handle_b64        => $body->{response}{userHandle},
			token_binding_id_b64   => undef,
		);
	};
	if ($@) {
		( my $msg = $@ ) =~ s/ at \S+ line \d+\.?\s*$//;
		$self->rate_fail('passkey');
		return $self->render( json => { error => "Verification failed: $msg" }, status => 401 );
	}
	$self->rate_reset('passkey');

	# Update sign count and last-used timestamp (best-effort)
	$self->pt_call(
		sub {
			$self->pt->userPasskeyCredentialUpdate(
				{
					user         => $user,
					credentialId => $credential_id,
					signCount    => $result->{sign_count} // $cred->{signCount},
					backupState  => ( $result->{bs} // 0 ) ? 'TRUE' : 'FALSE',
				}
			);
		}
	);

	# Check whether TOTP is also required
	my $info;
	$self->pt_call( sub { $info = $self->pt->userSelfInfo( { user => $user } ) } );
	if ( $info && ( $info->{totpStatus} // '' ) eq 'active' ) {
		$self->session( admin_totp_pending_user => $user );
		return $self->render( json => { ok => 1, totp_required => 1 } );
	}

	$self->session( admin_user => $user );
	$self->render( json => { ok => 1 } );
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

	return unless $self->rate_guard( 'totp', user => $user, render => { template => 'admin/totp_challenge' } );

	my $code = $self->param('code') // '';

	my $ok;
	my $err = $self->pt_call( sub { $ok = $self->pt->userTotpVerify( { user => $user, code => $code } ) } );
	if ( $err || !$ok ) {
		$self->rate_fail( 'totp', user => $user );
		$self->flash( error => 'Invalid TOTP code. Please try again.' );
		return $self->redirect_to('admin_totp_challenge');
	}
	$self->rate_reset( 'totp', user => $user );

	delete $self->session->{admin_totp_pending_user};
	$self->session( admin_user => $user );
	$self->redirect_to('users_index');
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
