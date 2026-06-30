package App::Nisaba::Web::Controller::OIDC;

use Mojo::Base 'Mojolicious::Controller';

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

sub create {
	my $self = shift;

	my %params;
	$params{clientId}        = $self->param('clientId')        // '';
	$params{clientSecret}    = $self->param('clientSecret')    // '';
	$params{clientName}      = $self->param('clientName')      // '';
	$params{applicationType} = $self->param('applicationType') // 'web';
	$params{authMethod}      = $self->param('authMethod')      // '';
	$params{subjectType}     = $self->param('subjectType')     // '';
	$params{clientURI}       = $self->param('clientURI')       // '';

	# Multi-value fields: split textarea lines into arrayrefs
	my $redirect_text = $self->param('redirectURIs') // '';
	$params{redirectURIs} = [ grep { $_ ne '' } split /\r?\n/, $redirect_text ];

	my $scope_text = $self->param('scopes') // '';
	$params{scopes} = [ grep { $_ ne '' } split /[\s,]+/, $scope_text ];

	my $grant_text = $self->param('grantTypes') // '';
	$params{grantTypes} = [ grep { $_ ne '' } split /[\s,]+/, $grant_text ];

	my $response_text = $self->param('responseTypes') // '';
	$params{responseTypes} = [ grep { $_ ne '' } split /\r?\n/, $response_text ];

	my $contact_text = $self->param('contacts') // '';
	$params{contacts} = [ grep { $_ ne '' } split /\r?\n/, $contact_text ];

	# Remove empty strings so addOIDCClient uses defaults
	for my $key (qw(clientSecret clientName applicationType authMethod subjectType clientURI)) {
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

	$self->flash( success => "OIDC client '$params{clientId}' added successfully." );
	$self->redirect_to('oidc_index');
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

	if ( exists $single_attrs{$action} ) {
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
