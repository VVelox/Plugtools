package App::Nisaba::Web::Controller::OIDC;

use Mojo::Base 'Mojolicious::Controller';
use Crypt::PK::RSA;
use Crypt::PRNG  qw(random_string_from);
use MIME::Base64 qw(encode_base64url);
use Mojo::JSON   qw(encode_json);

sub index {
	my $self = shift;

	my $clients;
	eval { $clients = $self->pt->getOIDCClients };
	if ($@) {
		# stash, not flash — flash only surfaces on the next request
		$self->stash( flash_error => "Failed to fetch OIDC clients: $@" );
		$clients = [];
	}

	my @sorted
		= sort { ( $a->get_value('oidcClientId') // '' ) cmp( $b->get_value('oidcClientId') // '' ) } @{$clients};
	$self->render( template => 'oidc/index', clients => \@sorted );
} ## end sub index

sub add {
	my $self = shift;
	$self->render( template => 'oidc/add' );
}

sub _generate_id {
	return random_string_from( join( '', 'a' .. 'z', '0' .. '9' ), 24 );
}

sub _generate_secret {
	return random_string_from( join( '', 'A' .. 'Z', 'a' .. 'z', '0' .. '9', '-', '_' ), 48 );
}

sub _generate_kid {
	return random_string_from( join( '', 'a' .. 'z', '0' .. '9' ), 16 );
}

# Absolute-URI check shared by create and the add-URI update actions.
sub _valid_absolute_uri {
	my ($uri) = @_;
	return defined $uri && $uri =~ m{^[A-Za-z][A-Za-z0-9+.-]*:} && $uri !~ /\s/;
}

# Generate a new RSA private key as a JWK hashref with kid/use/alg metadata.
sub _generate_jwk {
	my $rsa = Crypt::PK::RSA->new;
	$rsa->generate_key( 256, 65537 );    # 2048-bit key

	# export_key_jwk returns a JSON string; decode and add metadata
	my $priv_hash = Mojo::JSON::decode_json( $rsa->export_key_jwk('private') );
	$priv_hash->{kid} = _generate_kid();
	$priv_hash->{use} = 'sig';
	$priv_hash->{alg} = 'RS256';
	return $priv_hash;
} ## end sub _generate_jwk

# Generate an RSA key pair and return a JWK Set JSON string (with private key).
sub _generate_jwks {
	return encode_json( { keys => [ _generate_jwk() ] } );
}

# Rotate a client's JWK Set: a fresh private key goes first (the SSO provider
# signs with the first key holding private material), and previous keys are
# retained as public-only entries so ID tokens signed before the rotation keep
# verifying against the published JWKS. At most two old keys are kept.
sub _rotate_jwks {
	my ($old_json) = @_;

	my @retained;
	my $old = $old_json ? eval { Mojo::JSON::decode_json($old_json) } : undef;
	if ( $old && ref $old->{keys} eq 'ARRAY' ) {
		for my $key ( @{ $old->{keys} } ) {
			next unless ref $key eq 'HASH';
			my %pub = map { $_ => $key->{$_} } grep { defined $key->{$_} } qw(kty n e kid use alg);
			push @retained, \%pub if defined $pub{n} && defined $pub{e};
			last if @retained >= 2;
		}
	}

	return encode_json( { keys => [ _generate_jwk(), @retained ] } );
} ## end sub _rotate_jwks

sub create {
	my $self = shift;

	# Reject configurations the SSO provider will refuse to serve.
	my $clientType = $self->param('clientType') // 'confidential';
	if ( $clientType ne 'confidential' && $clientType ne 'public' ) {
		$self->flash( error => "Unknown client type '$clientType'." );
		return $self->redirect_to('oidc_add');
	}

	my $signingAlg = $self->param('signingAlg') // '';
	if ( $signingAlg ne '' && $signingAlg ne 'RS256' && $signingAlg ne 'HS256' ) {
		$self->flash(
			error => "Unsupported signing algorithm '$signingAlg' — the SSO provider supports RS256 and HS256. "
				. 'Unsigned (none) ID tokens are not permitted.' );
		return $self->redirect_to('oidc_add');
	}
	if ( $clientType eq 'public' && $signingAlg eq 'HS256' ) {
		$self->flash( error =>
				'HS256 signs ID tokens with the client secret, but public clients have no secret. Use RS256 for public clients.'
		);
		return $self->redirect_to('oidc_add');
	}

	my $redirect_text = $self->param('redirectURIs') // '';
	my @redirectURIs  = grep { $_ ne '' } map { s/^\s+|\s+$//gr } split /\r?\n/, $redirect_text;
	if ( !@redirectURIs ) {
		$self->flash( error => 'At least one redirect URI is required.' );
		return $self->redirect_to('oidc_add');
	}
	for my $uri (@redirectURIs) {
		unless ( _valid_absolute_uri($uri) ) {
			$self->flash( error => "Invalid redirect URI '$uri' — must be an absolute URI." );
			return $self->redirect_to('oidc_add');
		}
	}

	# Auto-generate client ID
	my $clientId = _generate_id();

	# Client type determines secret and auth method
	my $clientSecret;
	my $authMethod;
	if ( $clientType eq 'public' ) {
		$authMethod = 'none';
	} else {
		$clientSecret = _generate_secret();
		$authMethod   = 'client_secret_basic';
	}

	my %params;
	$params{clientId}     = $clientId;
	$params{clientSecret} = $clientSecret if defined $clientSecret;
	$params{clientName}   = $self->param('clientName') // '';
	$params{authMethod}   = $authMethod;

	$params{idTokenSignedResponseAlg} = $signingAlg if $signingAlg ne '';

	# Application type (derived from client type for convenience)
	$params{applicationType} = $self->param('applicationType') // 'web';

	$params{subjectType} = $self->param('subjectType') // '';
	$params{clientURI}   = $self->param('clientURI')   // '';

	$params{redirectURIs} = \@redirectURIs;

	my $scope_text = $self->param('scopes') // '';
	$params{scopes} = [ grep { $_ ne '' } split /[\s,]+/, $scope_text ];

	my $grant_text = $self->param('grantTypes') // '';
	$params{grantTypes} = [ grep { $_ ne '' } split /[\s,]+/, $grant_text ];

	$params{responseTypes} = [ grep { $_ ne '' } @{ $self->every_param('responseTypes') } ];

	my $contact_text = $self->param('contacts') // '';
	$params{contacts} = [ grep { $_ ne '' } split /\r?\n/, $contact_text ];

	# Remove empty strings so addOIDCClient uses defaults
	for my $key (qw(clientName applicationType subjectType clientURI)) {
		delete $params{$key} if !defined $params{$key} || $params{$key} eq '';
	}
	for my $key (qw(redirectURIs scopes grantTypes responseTypes contacts)) {
		delete $params{$key} unless ref $params{$key} eq 'ARRAY' && @{ $params{$key} };
	}

	my $error = $self->pt_call( sub { $self->pt->addOIDCClient( \%params ) } );
	if ($error) {
		$self->flash( error => "Failed to add OIDC client: $error" );
		return $self->redirect_to('oidc_add');
	}

	# Generate and store RSA key pair for token signing
	my $priv_jwks  = _generate_jwks();
	my $jwks_error = $self->pt_call(
		sub {
			$self->pt->oidcClientUpdate(
				{
					clientId  => $clientId,
					attribute => 'oidcJwks',
					value     => $priv_jwks,
				}
			);
		}
	);
	if ($jwks_error) {
		return $self->_render_show(
			$clientId,
			flash_error   => "Client created but key generation failed: $jwks_error",
			new_client_id => $clientId,
			( defined $clientSecret ? ( new_client_secret => $clientSecret ) : () ),
		);
	}

	$self->_render_show(
		$clientId,
		flash_success => "OIDC client created successfully.",
		new_client_id => $clientId,
		( defined $clientSecret ? ( new_client_secret => $clientSecret ) : () ),
	);
} ## end sub create

# Render the show page directly instead of redirect+flash. Generated
# credentials are passed via the stash so they never transit the session
# cookie, which is signed but not encrypted.
sub _render_show {
	my ( $self, $clientId, %stash ) = @_;

	my $entry;
	eval { $entry = $self->pt->getOIDCClientEntry( { clientId => $clientId } ) };
	if ( $@ || $self->pt->error || !$entry ) {
		return $self->redirect_to( 'oidc_show', clientId => $clientId );
	}

	$self->render(
		template => 'oidc/show',
		entry    => $entry,
		clientId => $clientId,
		%stash,
	);
} ## end sub _render_show

sub show {
	my $self     = shift;
	my $clientId = $self->param('clientId');

	my $entry;
	eval { $entry = $self->pt->getOIDCClientEntry( { clientId => $clientId } ) };
	if ( $@ || $self->pt->error || !$entry ) {
		my $msg = $@ || $self->pt->errorString || "Client '$clientId' not found";
		$self->flash( error => "Failed to fetch OIDC client: $msg" );
		return $self->redirect_to('oidc_index');
	}

	$self->render(
		template => 'oidc/show',
		entry    => $entry,
		clientId => $clientId,
	);
} ## end sub show

sub update {
	my $self     = shift;
	my $clientId = $self->param('clientId');
	my $action   = $self->param('action') // '';

	# Reject updates that would leave the client in a state the SSO
	# provider refuses to serve.
	my %secret_auth = map { $_ => 1 } qw(client_secret_basic client_secret_post);
	if ( $action eq 'authMethod' || $action eq 'idTokenSignedResponseAlg' || $action eq 'clientSecret' ) {
		my $value = $self->param('value') // '';

		my $veto;
		if ( $action eq 'authMethod' && !$secret_auth{$value} && $value ne 'none' ) {
			# client_secret_jwt / private_key_jwt included: the SSO provider's
			# token endpoint does not implement them and fails closed on clients
			# registered for an unimplemented method.
			$veto = "Unsupported token endpoint auth method '$value' — the SSO provider supports "
				. 'client_secret_basic, client_secret_post, and none.';
		} elsif ( $action eq 'idTokenSignedResponseAlg'
			&& $value ne 'RS256'
			&& $value ne 'HS256' )
		{
			# 'none' (unsigned) and clearing the value (which would fall back to
			# unsigned) are rejected: an admin-managed client must sign its tokens.
			$veto = "Unsupported signing algorithm '$value' — the SSO provider supports RS256 and HS256. "
				. 'Unsigned (none) ID tokens are not permitted.';
		}

		my $entry;
		if ( !$veto ) {
			eval { $entry = $self->pt->getOIDCClientEntry( { clientId => $clientId } ) };
		}
		if ($entry) {
			my $has_secret = ( $entry->get_value('oidcClientSecret') // '' ) ne '';
			my $has_jwks   = ( $entry->get_value('oidcJwks')         // '' ) ne '';
			if ( $action eq 'authMethod' && $secret_auth{$value} && !$has_secret ) {
				$veto = "Auth method '$value' requires a client secret — generate one first.";
			} elsif ( $action eq 'idTokenSignedResponseAlg' ) {
				if ( $value eq 'HS256' && !$has_secret ) {
					$veto = 'HS256 signs with the client secret, but this client has none — generate a secret first.';
				} elsif ( $value eq 'RS256' && !$has_jwks ) {
					$veto = 'RS256 requires a signing key pair — generate keys first.';
				}
			} elsif ( $action eq 'clientSecret' && $value eq '' ) {
				my $am  = $entry->get_value('oidcTokenEndpointAuthMethod')  // '';
				my $alg = $entry->get_value('oidcIdTokenSignedResponseAlg') // '';
				if ( $secret_auth{$am} || $alg eq 'HS256' ) {
					$veto = 'Cannot clear the client secret while the auth method or signing algorithm depends on it.';
				}
			}
		} ## end if ($entry)

		if ($veto) {
			$self->flash( error => $veto );
			return $self->redirect_to( 'oidc_show', clientId => $clientId );
		}
	} ## end if ( $action eq 'authMethod' || $action eq...)

	my $error;

	# Single-value attribute updates
	my %single_attrs = (
		clientName                   => 'oidcClientName',
		clientSecret                 => 'oidcClientSecret',
		clientURI                    => 'oidcClientURI',
		logoURI                      => 'oidcLogoURI',
		policyURI                    => 'oidcPolicyURI',
		tosURI                       => 'oidcTosURI',
		applicationType              => 'oidcApplicationType',
		authMethod                   => 'oidcTokenEndpointAuthMethod',
		subjectType                  => 'oidcSubjectType',
		defaultMaxAge                => 'oidcDefaultMaxAge',
		requireAuthTime              => 'oidcRequireAuthTime',
		jwksURI                      => 'oidcJwksURI',
		initiateLoginURI             => 'oidcInitiateLoginURI',
		sectorIdentifierURI          => 'oidcSectorIdentifierURI',
		idTokenSignedResponseAlg     => 'oidcIdTokenSignedResponseAlg',
		idTokenEncryptedResponseAlg  => 'oidcIdTokenEncryptedResponseAlg',
		idTokenEncryptedResponseEnc  => 'oidcIdTokenEncryptedResponseEnc',
		userInfoSignedResponseAlg    => 'oidcUserInfoSignedResponseAlg',
		userInfoEncryptedResponseAlg => 'oidcUserInfoEncryptedResponseAlg',
		userInfoEncryptedResponseEnc => 'oidcUserInfoEncryptedResponseEnc',
		requestObjectSigningAlg      => 'oidcRequestObjectSigningAlg',
		requestObjectEncryptionAlg   => 'oidcRequestObjectEncryptionAlg',
		requestObjectEncryptionEnc   => 'oidcRequestObjectEncryptionEnc',
		tokenEndpointAuthSigningAlg  => 'oidcTokenEndpointAuthSigningAlg',
		softwareId                   => 'oidcSoftwareId',
		softwareVersion              => 'oidcSoftwareVersion',
	);

	if ( $action eq 'regenerateSecret' ) {
		my $new_secret = _generate_secret();
		$error = $self->pt_call(
			sub {
				$self->pt->oidcClientUpdate(
					{
						clientId  => $clientId,
						attribute => 'oidcClientSecret',
						value     => $new_secret,
					}
				);
			}
		);
		if ( !$error ) {
			return $self->_render_show(
				$clientId,
				flash_success     => "Client secret regenerated.",
				new_client_secret => $new_secret,
			);
		}
	} elsif ( $action eq 'regenerateKeys' ) {
		# Rotate rather than replace: old public keys stay in the set so
		# already-issued ID tokens keep verifying during the overlap window.
		my $entry;
		eval { $entry = $self->pt->getOIDCClientEntry( { clientId => $clientId } ) };
		my $new_jwks = _rotate_jwks( $entry ? $entry->get_value('oidcJwks') : undef );
		$error = $self->pt_call(
			sub {
				$self->pt->oidcClientUpdate(
					{
						clientId  => $clientId,
						attribute => 'oidcJwks',
						value     => $new_jwks,
					}
				);
			}
		);
		if ( !$error ) {
			$self->flash( success => 'Signing key pair rotated; previous public keys retained for verification.' );
			return $self->redirect_to( 'oidc_show', clientId => $clientId );
		}
	} elsif ( exists $single_attrs{$action} ) {
		$error = $self->pt_call(
			sub {
				$self->pt->oidcClientUpdate(
					{
						clientId  => $clientId,
						attribute => $single_attrs{$action},
						value     => $self->param('value'),
					}
				);
			}
		);
	} elsif ( $action eq 'redirectURI_add' ) {
		# Same validation as create: a relative or whitespace-containing URI
		# would never match an exact-comparison redirect check anyway.
		my $uri = $self->param('value') // '';
		unless ( _valid_absolute_uri($uri) ) {
			$self->flash( error => "Invalid redirect URI '$uri' — must be an absolute URI." );
			return $self->redirect_to( 'oidc_show', clientId => $clientId );
		}
		$error = $self->pt_call(
			sub {
				$self->pt->oidcClientAddMultiValue(
					{ clientId => $clientId, attribute => 'oidcRedirectURI', value => $uri } );
			}
		);
	} elsif ( $action eq 'redirectURI_remove' ) {
		$error = $self->pt_call(
			sub {
				$self->pt->oidcClientRemoveMultiValue(
					{ clientId => $clientId, attribute => 'oidcRedirectURI', value => $self->param('value') } );
			}
		);
	} elsif ( $action eq 'scope_add' ) {
		$error = $self->pt_call(
			sub {
				$self->pt->oidcClientAddMultiValue(
					{ clientId => $clientId, attribute => 'oidcScope', value => $self->param('value') } );
			}
		);
	} elsif ( $action eq 'scope_remove' ) {
		$error = $self->pt_call(
			sub {
				$self->pt->oidcClientRemoveMultiValue(
					{ clientId => $clientId, attribute => 'oidcScope', value => $self->param('value') } );
			}
		);
	} elsif ( $action eq 'grantType_add' ) {
		$error = $self->pt_call(
			sub {
				$self->pt->oidcClientAddMultiValue(
					{ clientId => $clientId, attribute => 'oidcGrantType', value => $self->param('value') } );
			}
		);
	} elsif ( $action eq 'grantType_remove' ) {
		$error = $self->pt_call(
			sub {
				$self->pt->oidcClientRemoveMultiValue(
					{ clientId => $clientId, attribute => 'oidcGrantType', value => $self->param('value') } );
			}
		);
	} elsif ( $action eq 'responseType_add' ) {
		$error = $self->pt_call(
			sub {
				$self->pt->oidcClientAddMultiValue(
					{ clientId => $clientId, attribute => 'oidcResponseType', value => $self->param('value') } );
			}
		);
	} elsif ( $action eq 'responseType_remove' ) {
		$error = $self->pt_call(
			sub {
				$self->pt->oidcClientRemoveMultiValue(
					{ clientId => $clientId, attribute => 'oidcResponseType', value => $self->param('value') } );
			}
		);
	} elsif ( $action eq 'contact_add' ) {
		$error = $self->pt_call(
			sub {
				$self->pt->oidcClientAddMultiValue(
					{ clientId => $clientId, attribute => 'oidcContact', value => $self->param('value') } );
			}
		);
	} elsif ( $action eq 'contact_remove' ) {
		$error = $self->pt_call(
			sub {
				$self->pt->oidcClientRemoveMultiValue(
					{ clientId => $clientId, attribute => 'oidcContact', value => $self->param('value') } );
			}
		);
	} elsif ( $action eq 'postLogoutRedirectURI_add' ) {
		my $uri = $self->param('value') // '';
		unless ( _valid_absolute_uri($uri) ) {
			$self->flash( error => "Invalid post-logout redirect URI '$uri' — must be an absolute URI." );
			return $self->redirect_to( 'oidc_show', clientId => $clientId );
		}
		$error = $self->pt_call(
			sub {
				$self->pt->oidcClientAddMultiValue(
					{
						clientId  => $clientId,
						attribute => 'oidcPostLogoutRedirectURI',
						value     => $uri
					}
				);
			}
		);
	} elsif ( $action eq 'postLogoutRedirectURI_remove' ) {
		$error = $self->pt_call(
			sub {
				$self->pt->oidcClientRemoveMultiValue(
					{
						clientId  => $clientId,
						attribute => 'oidcPostLogoutRedirectURI',
						value     => $self->param('value')
					}
				);
			}
		);
	} else {
		$self->flash( error => "Unknown action: $action" );
		return $self->redirect_to( 'oidc_show', clientId => $clientId );
	}

	if ($error) {
		$self->flash( error => "Failed to update OIDC client '$clientId': $error" );
		return $self->redirect_to( 'oidc_show', clientId => $clientId );
	}

	$self->flash( success => "OIDC client '$clientId' updated successfully." );
	$self->redirect_to( 'oidc_show', clientId => $clientId );
} ## end sub update

sub delete {
	my $self     = shift;
	my $clientId = $self->param('clientId');

	my $error = $self->pt_call( sub { $self->pt->deleteOIDCClient($clientId) } );
	if ($error) {
		$self->flash( error => "Failed to delete OIDC client '$clientId': $error" );
		return $self->redirect_to( 'oidc_show', clientId => $clientId );
	}

	$self->flash( success => "OIDC client '$clientId' deleted successfully." );
	$self->redirect_to('oidc_index');
} ## end sub delete

1;
