package App::Nisaba::Web::Controller::OIDC;

use Mojo::Base 'Mojolicious::Controller';
use Crypt::PK::RSA;
use MIME::Base64 qw(encode_base64url);
use Mojo::JSON   qw(encode_json);

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
		$self->flash( error => "Failed to fetch OIDC clients: $@" );
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
	my @chars = ( 'a' .. 'z', '0' .. '9' );
	my $id    = '';
	$id .= $chars[ rand @chars ] for 1 .. 24;
	return $id;
}

sub _generate_secret {
	my @chars = ( 'A' .. 'Z', 'a' .. 'z', '0' .. '9', '-', '_' );
	my $sec   = '';
	$sec .= $chars[ rand @chars ] for 1 .. 48;
	return $sec;
}

sub _generate_kid {
	my @chars = ( 'a' .. 'z', '0' .. '9' );
	my $kid   = '';
	$kid .= $chars[ rand @chars ] for 1 .. 16;
	return $kid;
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

	# Auto-generate client ID
	my $clientId = _generate_id();

	# Client type determines secret and auth method
	my $clientType = $self->param('clientType') // 'confidential';
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

	# Signing algorithm
	my $signingAlg = $self->param('signingAlg') // '';
	$params{idTokenSignedResponseAlg} = $signingAlg if $signingAlg ne '';

	# Application type (derived from client type for convenience)
	$params{applicationType} = $self->param('applicationType') // 'web';

	$params{subjectType} = $self->param('subjectType') // '';
	$params{clientURI}   = $self->param('clientURI')   // '';

	# Multi-value fields: split textarea lines into arrayrefs
	my $redirect_text = $self->param('redirectURIs') // '';
	$params{redirectURIs} = [ grep { $_ ne '' } split /\r?\n/, $redirect_text ];

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
		$self->flash( error => "Client created but key generation failed: $jwks_error" );
		return $self->redirect_to( 'oidc_show', clientId => $clientId );
	}

	# Flash the generated credentials so the show page can display them once
	$self->flash( success           => "OIDC client created successfully." );
	$self->flash( new_client_id     => $clientId );
	$self->flash( new_client_type   => $clientType );
	$self->flash( new_client_secret => $clientSecret ) if defined $clientSecret;

	$self->redirect_to( 'oidc_show', clientId => $clientId );
} ## end sub create

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
			$self->flash( success           => "Client secret regenerated." );
			$self->flash( new_client_secret => $new_secret );
			return $self->redirect_to( 'oidc_show', clientId => $clientId );
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
