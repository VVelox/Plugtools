package App::Nisaba::Web::Controller::OIDC;

use Mojo::Base 'Mojolicious::Controller';
use Crypt::PK::RSA;
use Crypt::PRNG   qw(random_string_from);
use MIME::Base64  qw(encode_base64url);
use Mojo::JSON    qw(encode_json);

sub _pt_call {
	my ( $self, $code ) = @_;
	eval { $code->() };
	return $@ if $@;
	if ( $self->pt->error ) {
		return $self->pt->errorString || ( 'Error code ' . $self->pt->error );
	}
	return '';
}

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

# Generate an RSA key pair and return a JWK Set JSON string (with private key).
sub _generate_jwks {
	my $rsa = Crypt::PK::RSA->new;
	$rsa->generate_key( 256, 65537 );    # 2048-bit key

	my $kid = _generate_kid();

	# export_key_jwk returns a JSON string; decode, add metadata, re-encode
	my $priv_json = $rsa->export_key_jwk('private');
	my $priv_hash = Mojo::JSON::decode_json($priv_json);
	$priv_hash->{kid} = $kid;
	$priv_hash->{use} = 'sig';
	$priv_hash->{alg} = 'RS256';

	my $priv_jwks = encode_json( { keys => [$priv_hash] } );
	return $priv_jwks;
} ## end sub _generate_jwks

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
		if ( $uri !~ m{^[A-Za-z][A-Za-z0-9+.-]*:} || $uri =~ /\s/ ) {
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

	my $error = $self->_pt_call( sub { $self->pt->addOIDCClient( \%params ) } );
	if ($error) {
		$self->flash( error => "Failed to add OIDC client: $error" );
		return $self->redirect_to('oidc_add');
	}

	# Generate and store RSA key pair for token signing
	my $priv_jwks = _generate_jwks();
	my $jwks_error = $self->_pt_call(
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
	my %secret_auth = map { $_ => 1 } qw(client_secret_basic client_secret_post client_secret_jwt);
	if ( $action eq 'authMethod' || $action eq 'idTokenSignedResponseAlg' || $action eq 'clientSecret' ) {
		my $value = $self->param('value') // '';

		my $veto;
		if ( $action eq 'authMethod' && !$secret_auth{$value} && $value ne 'private_key_jwt' && $value ne 'none' ) {
			$veto = "Unknown token endpoint auth method '$value'.";
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
			my $has_jwks   = ( $entry->get_value('oidcJwks') // '' ) ne '';
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
		}

		if ($veto) {
			$self->flash( error => $veto );
			return $self->redirect_to( 'oidc_show', clientId => $clientId );
		}
	} ## end guard

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
		$error = $self->_pt_call(
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
		my $new_jwks = _generate_jwks();
		$error = $self->_pt_call(
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
			$self->flash( success => "Signing key pair regenerated." );
			return $self->redirect_to( 'oidc_show', clientId => $clientId );
		}
	} elsif ( exists $single_attrs{$action} ) {
		$error = $self->_pt_call(
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
		$error = $self->_pt_call(
			sub {
				$self->pt->oidcClientAddMultiValue(
					{ clientId => $clientId, attribute => 'oidcRedirectURI', value => $self->param('value') } );
			}
		);
	} elsif ( $action eq 'redirectURI_remove' ) {
		$error = $self->_pt_call(
			sub {
				$self->pt->oidcClientRemoveMultiValue(
					{ clientId => $clientId, attribute => 'oidcRedirectURI', value => $self->param('value') } );
			}
		);
	} elsif ( $action eq 'scope_add' ) {
		$error = $self->_pt_call(
			sub {
				$self->pt->oidcClientAddMultiValue(
					{ clientId => $clientId, attribute => 'oidcScope', value => $self->param('value') } );
			}
		);
	} elsif ( $action eq 'scope_remove' ) {
		$error = $self->_pt_call(
			sub {
				$self->pt->oidcClientRemoveMultiValue(
					{ clientId => $clientId, attribute => 'oidcScope', value => $self->param('value') } );
			}
		);
	} elsif ( $action eq 'grantType_add' ) {
		$error = $self->_pt_call(
			sub {
				$self->pt->oidcClientAddMultiValue(
					{ clientId => $clientId, attribute => 'oidcGrantType', value => $self->param('value') } );
			}
		);
	} elsif ( $action eq 'grantType_remove' ) {
		$error = $self->_pt_call(
			sub {
				$self->pt->oidcClientRemoveMultiValue(
					{ clientId => $clientId, attribute => 'oidcGrantType', value => $self->param('value') } );
			}
		);
	} elsif ( $action eq 'responseType_add' ) {
		$error = $self->_pt_call(
			sub {
				$self->pt->oidcClientAddMultiValue(
					{ clientId => $clientId, attribute => 'oidcResponseType', value => $self->param('value') } );
			}
		);
	} elsif ( $action eq 'responseType_remove' ) {
		$error = $self->_pt_call(
			sub {
				$self->pt->oidcClientRemoveMultiValue(
					{ clientId => $clientId, attribute => 'oidcResponseType', value => $self->param('value') } );
			}
		);
	} elsif ( $action eq 'contact_add' ) {
		$error = $self->_pt_call(
			sub {
				$self->pt->oidcClientAddMultiValue(
					{ clientId => $clientId, attribute => 'oidcContact', value => $self->param('value') } );
			}
		);
	} elsif ( $action eq 'contact_remove' ) {
		$error = $self->_pt_call(
			sub {
				$self->pt->oidcClientRemoveMultiValue(
					{ clientId => $clientId, attribute => 'oidcContact', value => $self->param('value') } );
			}
		);
	} elsif ( $action eq 'postLogoutRedirectURI_add' ) {
		$error = $self->_pt_call(
			sub {
				$self->pt->oidcClientAddMultiValue(
					{
						clientId  => $clientId,
						attribute => 'oidcPostLogoutRedirectURI',
						value     => $self->param('value')
					}
				);
			}
		);
	} elsif ( $action eq 'postLogoutRedirectURI_remove' ) {
		$error = $self->_pt_call(
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

	my $error = $self->_pt_call( sub { $self->pt->deleteOIDCClient($clientId) } );
	if ($error) {
		$self->flash( error => "Failed to delete OIDC client '$clientId': $error" );
		return $self->redirect_to( 'oidc_show', clientId => $clientId );
	}

	$self->flash( success => "OIDC client '$clientId' deleted successfully." );
	$self->redirect_to('oidc_index');
} ## end sub delete

1;
