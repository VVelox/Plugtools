package App::Nisaba::WebSelfService::Controller::SelfService;

use Mojo::Base 'Mojolicious::Controller', -signatures;
use Mojo::Util qw(hmac_sha1_sum b64_encode b64_decode url_escape);

=head1 NAME

App::Nisaba::WebSelfService::Controller::SelfService - Self-service portal controller

=head1 DESCRIPTION

Handles login, logout, password change, SSH key management, and
password-reset-via-email for the self-service portal.

=cut

# --------------------------------------------------------------------------- #
# Auth middleware
# --------------------------------------------------------------------------- #

sub require_login ($self) {
	return 1 if $self->session('user');
	$self->redirect_to('login');
	return undef;
}

# --------------------------------------------------------------------------- #
# Login / logout
# --------------------------------------------------------------------------- #

sub login_form ($self) {
	$self->render( template => 'selfservice/login' );
}

sub login ($self) {
	my $user = $self->param('user') // '';
	my $pass = $self->param('pass') // '';

	my $err = $self->pt_call( sub { $self->pt->userVerifyPassword( { user => $user, password => $pass } ) } );
	if ($err) {
		$self->flash( error => 'Invalid username or password.' );
		return $self->redirect_to('login');
	}

	# Check whether TOTP is active for this user
	my $info;
	$self->pt_call( sub { $info = $self->pt->userSelfInfo( { user => $user } ) } );
	if ( $info && ( $info->{totpStatus} // '' ) eq 'active' ) {
		$self->session( totp_pending_user => $user );
		return $self->redirect_to('totp_challenge');
	}

	$self->session( user => $user );
	$self->redirect_to('dashboard');
} ## end sub login

sub logout ($self) {
	$self->session( expires => 1 );
	$self->redirect_to('login');
}

sub totp_challenge_form ($self) {
	unless ( $self->session('totp_pending_user') ) {
		return $self->redirect_to('login');
	}
	$self->render( template => 'selfservice/totp_challenge' );
}

sub totp_challenge ($self) {
	my $user = $self->session('totp_pending_user');
	unless ($user) {
		return $self->redirect_to('login');
	}

	my $code = $self->param('code') // '';

	my $ok;
	my $err = $self->pt_call( sub { $ok = $self->pt->userTotpVerify( { user => $user, code => $code } ) } );
	if ( $err || !$ok ) {
		$self->flash( error => 'Invalid TOTP code. Please try again.' );
		return $self->redirect_to('totp_challenge');
	}

	delete $self->session->{totp_pending_user};
	$self->session( user => $user );
	$self->redirect_to('dashboard');
} ## end sub totp_challenge

# --------------------------------------------------------------------------- #
# Dashboard
# --------------------------------------------------------------------------- #

sub dashboard ($self) {
	my $user = $self->session('user');

	my $info;
	my $err = $self->pt_call( sub { $info = $self->pt->userSelfInfo( { user => $user } ) } );
	if ($err) {
		$self->flash( error => "Could not load your account information: $err" );
		return $self->redirect_to('login');
	}

	my $lpk_schema  = $self->pt->ldapPublicKeyAvailable ? 1 : 0;
	my $totp_schema = $self->pt->totpSchemaAvailable    ? 1 : 0;

	my ( $totp_qr_b64, $totp_uri ) = ( undef, undef );
	if ( $totp_schema && $info->{objectClasses}{totpuser} && ( $info->{totpStatus} // '' ) eq 'pending' ) {
		my $totp_full;
		my $terr = $self->pt_call( sub { $totp_full = $self->pt->userTotpInfoGet( { user => $user } ) } );
		if ( !$terr && $totp_full && defined $totp_full->{totpSecret} ) {
			my %totp_args = (
				secret    => $totp_full->{totpSecret},
				user      => $user,
				algorithm => $totp_full->{totpAlgorithm},
				period    => $totp_full->{totpPeriod},
				digits    => $totp_full->{totpDigits},
			);
			eval { $totp_qr_b64 = $self->pt->totpQRCodeBase64( \%totp_args ) };
			eval { $totp_uri    = $self->pt->totpURI( \%totp_args ) };
		} ## end if ( !$terr && $totp_full && defined $totp_full...)
	} ## end if ( $totp_schema && $info->{objectClasses...})

	$self->render(
		template    => 'selfservice/dashboard',
		user        => $user,
		info        => $info,
		lpk_schema  => $lpk_schema,
		totp_schema => $totp_schema,
		totp_qr_b64 => $totp_qr_b64,
		totp_uri    => $totp_uri,
	);
} ## end sub dashboard

# --------------------------------------------------------------------------- #
# Password change
# --------------------------------------------------------------------------- #

sub change_password ($self) {
	my $user     = $self->session('user');
	my $current  = $self->param('current')  // '';
	my $new_pass = $self->param('new_pass') // '';
	my $confirm  = $self->param('confirm')  // '';

	if ( $new_pass eq '' ) {
		$self->flash( error => 'New password must not be empty.' );
		return $self->redirect_to('dashboard');
	}
	if ( $new_pass ne $confirm ) {
		$self->flash( error => 'New password and confirmation do not match.' );
		return $self->redirect_to('dashboard');
	}

	# Verify current password first
	my $verify_err = $self->pt_call( sub { $self->pt->userVerifyPassword( { user => $user, password => $current } ) } );
	if ($verify_err) {
		$self->flash( error => 'Current password is incorrect.' );
		return $self->redirect_to('dashboard');
	}

	my $err = $self->pt_call( sub { $self->pt->userSetPassSelf( { user => $user, pass => $new_pass } ) } );
	if ($err) {
		$self->flash( error => "Password change failed: $err" );
		return $self->redirect_to('dashboard');
	}

	$self->flash( success => 'Password changed successfully.' );
	$self->redirect_to('dashboard');
} ## end sub change_password

# --------------------------------------------------------------------------- #
# SSH key management
# --------------------------------------------------------------------------- #

sub sshkey_enable ($self) {
	my $user = $self->session('user');

	my $err = $self->pt_call( sub { $self->pt->userConvertToLdapPublicKeySelf( { user => $user } ) } );
	if ($err) {
		$self->flash( error => "Could not enable SSH key storage: $err" );
	} else {
		$self->flash( success => 'SSH key storage enabled.' );
	}
	$self->redirect_to('dashboard');
} ## end sub sshkey_enable

sub sshkey_add ($self) {
	my $user = $self->session('user');
	my $key  = $self->param('key') // '';
	$key =~ s/[\r\n]+//g;

	if ( $key eq '' ) {
		$self->flash( error => 'SSH public key must not be empty.' );
		return $self->redirect_to('dashboard');
	}

	my $err = $self->pt_call( sub { $self->pt->userSSHPublicKeyAddSelf( { user => $user, key => $key } ) } );
	if ($err) {
		$self->flash( error => "Could not add SSH key: $err" );
	} else {
		$self->flash( success => 'SSH key added.' );
	}
	$self->redirect_to('dashboard');
} ## end sub sshkey_add

sub sshkey_remove ($self) {
	my $user = $self->session('user');
	my $key  = $self->param('key') // '';

	my $err = $self->pt_call( sub { $self->pt->userSSHPublicKeyRemoveSelf( { user => $user, key => $key } ) } );
	if ($err) {
		$self->flash( error => "Could not remove SSH key: $err" );
	} else {
		$self->flash( success => 'SSH key removed.' );
	}
	$self->redirect_to('dashboard');
} ## end sub sshkey_remove

# --------------------------------------------------------------------------- #
# TOTP
# --------------------------------------------------------------------------- #

sub totp_enable ($self) {
	my $user = $self->session('user');

	my $err = $self->pt_call( sub { $self->pt->userConvertToTotp( { user => $user } ) } );
	if ($err) {
		$self->flash( error => "Could not enable TOTP: $err" );
		return $self->redirect_to('dashboard');
	}

	$err = $self->pt_call( sub { $self->pt->userTotpGenerateSecret( { user => $user } ) } );
	if ($err) {
		$self->flash( error => "TOTP enabled but could not generate a secret: $err" );
		return $self->redirect_to('dashboard');
	}

	$self->flash( success => 'TOTP enabled. Scan the QR code below to enrol your authenticator app.' );
	$self->redirect_to('dashboard');
} ## end sub totp_enable

sub totp_generate ($self) {
	my $user = $self->session('user');

	my $err = $self->pt_call( sub { $self->pt->userTotpGenerateSecret( { user => $user } ) } );
	if ($err) {
		$self->flash( error => "Could not generate TOTP secret: $err" );
		return $self->redirect_to('dashboard');
	}

	$self->flash( success => 'New TOTP secret generated. Scan the QR code below to enrol your authenticator app.' );
	$self->redirect_to('dashboard');
} ## end sub totp_generate

sub totp_verify ($self) {
	my $user = $self->session('user');
	my $code = $self->param('code') // '';

	my $ok;
	my $err = $self->pt_call( sub { $ok = $self->pt->userTotpVerify( { user => $user, code => $code } ) } );
	if ( $err || !$ok ) {
		$self->flash( error => 'TOTP verification failed. Please check the code and try again.' );
		return $self->redirect_to('dashboard');
	}

	$self->pt_call( sub { $self->pt->userTotpStatusSet( { user => $user, status => 'active' } ) } );
	$self->pt_call( sub { $self->pt->userTotpEnrolledDateSet( { user => $user } ) } );

	$self->flash( success => 'TOTP verified and activated. Your account is now protected with MFA.' );
	$self->redirect_to('dashboard');
} ## end sub totp_verify

sub totp_scratch_replace ($self) {
	my $user = $self->session('user');

	my $codes;
	my $err = $self->pt_call( sub { $codes = $self->pt->userTotpScratchCodesReplace( { user => $user } ) } );
	if ($err) {
		$self->flash( error => "Could not generate scratch codes: $err" );
		return $self->redirect_to('dashboard');
	}

	$self->flash( new_scratch_codes => $codes );
	$self->redirect_to('dashboard');
} ## end sub totp_scratch_replace

# --------------------------------------------------------------------------- #
# Forgot / reset password
# --------------------------------------------------------------------------- #

sub forgot_form ($self) {
	unless ( $self->reset_available ) {
		$self->flash( error => 'Password reset by email is not configured on this server.' );
		return $self->redirect_to('login');
	}
	$self->session( expires => 1 );
	$self->render( template => 'selfservice/forgot' );
}

sub forgot ($self) {
	unless ( $self->reset_available ) {
		$self->flash( error => 'Password reset by email is not configured on this server.' );
		return $self->redirect_to('login');
	}

	my $user = $self->param('user') // '';

	# Always show the same message to prevent user enumeration
	my $ok_msg = 'If that username exists and has an email address on file, a reset link has been sent.';

	# Look up the user's email
	my $info;
	my $err = $self->pt_call( sub { $info = $self->pt->userSelfInfo( { user => $user } ) } );
	if ($err) {
		$self->flash( success => $ok_msg );
		return $self->redirect_to('forgot');
	}

	my $mail = $info->{mail};
	if ( !defined($mail) || $mail eq '' ) {
		$self->flash( success => $ok_msg );
		return $self->redirect_to('forgot');
	}

	# Generate a signed reset token: base64(user \0 expiry \0 sig)
	my $expiry  = time() + 3600;                              # 1 hour
	my $secret  = $self->app->secrets->[0];
	my $payload = $user . "\0" . $expiry;
	my $sig     = hmac_sha1_sum( $payload, $secret );
	my $token   = b64_encode( $payload . "\0" . $sig, '' );
	$token =~ tr|+/|,-|;                                      # URL-safe

	my $reset_url = $self->url_for('reset')->to_abs->to_string;
	$reset_url =~ s|/reset/?$||;
	$reset_url .= '/reset/' . url_escape($token);

	my $body = <<"END_BODY";
Someone (hopefully you) requested a password reset for your account "$user".

Click the link below to set a new password. The link expires in one hour.

$reset_url

If you did not request this, you can safely ignore this email.
END_BODY

	$self->pt->sendEmail(
		{
			to      => $mail,
			subject => 'Password reset request',
			body    => $body,
		}
	);

	$self->flash( success => $ok_msg );
	$self->redirect_to('forgot');
} ## end sub forgot

sub reset_form ($self) {
	my $token = $self->param('token') // '';
	my $user  = _verify_reset_token( $self, $token );
	if ( !defined($user) ) {
		$self->flash( error => 'This reset link is invalid or has expired.' );
		return $self->redirect_to('forgot');
	}
	$self->session( expires => 1 );
	$self->render( template => 'selfservice/reset', token => $token );
} ## end sub reset_form

sub reset ($self) {
	my $token = $self->param('token') // '';
	$self->session( expires => 1 );
	my $new_pass = $self->param('new_pass') // '';
	my $confirm  = $self->param('confirm')  // '';

	my $user = _verify_reset_token( $self, $token );
	if ( !defined($user) ) {
		$self->flash( error => 'This reset link is invalid or has expired.' );
		return $self->redirect_to('forgot');
	}

	if ( $new_pass eq '' ) {
		$self->flash( error => 'Password must not be empty.' );
		return $self->redirect_to( $self->url_for( 'reset', token => $token ) );
	}
	if ( $new_pass ne $confirm ) {
		$self->flash( error => 'Passwords do not match.' );
		return $self->redirect_to( $self->url_for( 'reset', token => $token ) );
	}

	my $err = $self->pt_call( sub { $self->pt->userSetPassSelf( { user => $user, pass => $new_pass } ) } );
	if ($err) {
		$self->flash( error => "Password reset failed: $err" );
		return $self->redirect_to( $self->url_for( 'reset', token => $token ) );
	}

	$self->flash( success => 'Password reset successfully. Please log in.' );
	$self->redirect_to('login');
} ## end sub reset

# --------------------------------------------------------------------------- #
# Private helpers
# --------------------------------------------------------------------------- #

sub _verify_reset_token {
	my ( $c, $token ) = @_;
	return undef unless defined($token) && $token ne '';

	$token =~ tr|,-|+/|;    # Undo URL-safe encoding
	my $raw = eval { b64_decode($token) };
	return undef if $@;

	my ( $user, $expiry, $sig ) = split /\0/, $raw, 3;
	return undef unless defined($user) && defined($expiry) && defined($sig);
	return undef if time() > $expiry;

	my $secret   = $c->app->secrets->[0];
	my $expected = hmac_sha1_sum( $user . "\0" . $expiry, $secret );
	return undef unless $sig eq $expected;

	return $user;
} ## end sub _verify_reset_token

1;
