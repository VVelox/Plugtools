package App::Nisaba::Web;

use Mojo::Base 'Mojolicious';
use File::ShareDir qw(dist_dir);
use App::Nisaba;
use App::Nisaba::WebSecret;
use App::Nisaba::WebCSRF;
use App::Nisaba::WebUtil ();

our $VERSION = '0.0.1';

sub startup {
	my $self = shift;

	my $share = dist_dir('App-Nisaba');
	push @{ $self->renderer->paths }, "$share/templates";
	push @{ $self->static->paths },   "$share/public";

	# Shared App::Nisaba instance. Config path via $ENV{NISABA_CONFIG} or default.
	my %pt_args;
	$pt_args{config} = $ENV{NISABA_CONFIG} if $ENV{NISABA_CONFIG};
	my $pt = App::Nisaba->new( \%pt_args );

	# Session secret — from config or NISABA_SECRET. Refuses to start rather
	# than sign sessions with a predictable default (see App::Nisaba::WebSecret).
	$self->secrets(
		[
			App::Nisaba::WebSecret::resolve(
				configured => $pt->{ini}->{''}->{websecret},
				env        => $ENV{NISABA_SECRET},
				app        => 'App::Nisaba::Web (admin portal)',
			)
		]
	);

	# Harden the session cookie: SameSite=Lax (explicit) and Secure (HTTPS-only).
	# Secure is on by default; disable it for plain-HTTP development or testing
	# with cookieSecure=0 in the config or NISABA_COOKIE_SECURE=0 in the env.
	$self->sessions->samesite('Lax');
	my $cookie_secure = $pt->{ini}->{''}->{cookieSecure} // $ENV{NISABA_COOKIE_SECURE} // 1;
	$self->sessions->secure( $cookie_secure ? 1 : 0 );

	# Helper to access the App::Nisaba instance
	$self->helper( pt => sub { $pt } );

	# Helper to call a pt method and return an error string (empty = success)
	$self->helper(
		pt_call => sub {
			my ( $c, $code ) = @_;
			eval { $code->() };
			return $@ if $@;
			if ( $c->pt->error ) {
				return $c->pt->errorString || ( 'Error code ' . $c->pt->error );
			}
			return '';
		}
	);

	# Helper: passkey login is available when the passkey schema is loaded
	$self->helper(
		passkey_login_available => sub {
			my ($c) = @_;
			return eval { $c->pt->passkeySchemaAvailable } ? 1 : 0;
		}
	);

	# CSRF: reject state-changing requests whose origin isn't our own, and
	# require the per-session synchronizer token on every such request.
	App::Nisaba::WebCSRF::install_origin_check($self);
	App::Nisaba::WebCSRF::install_token_check($self);

	# Brute-force rate limiting for the auth endpoints.
	App::Nisaba::WebUtil::install_rate_limiter($self);

	# Production Hypnotoad tuning from nisabarc / NISABA_HYPNOTOAD_* (see rc/).
	App::Nisaba::WebUtil::install_hypnotoad_config($self);

	my $r = $self->routes;

	# Public routes (no auth required)
	$r->get('/login')->to('auth#login_form')->name('admin_login');
	$r->post('/login')->to('auth#login')->name('admin_login_post');
	$r->get('/totp/challenge')->to('auth#totp_challenge_form')->name('admin_totp_challenge');
	$r->post('/totp/challenge')->to('auth#totp_challenge')->name('admin_totp_challenge_post');
	$r->get('/passkeys/login/start')->to('auth#passkey_login_start')->name('admin_passkey_login_start');
	$r->post('/passkeys/login/finish')->to('auth#passkey_login_finish')->name('admin_passkey_login_finish');

	# Authenticated routes — all admin pages sit behind require_login
	my $auth = $r->under('/')->to('auth#require_login');
	$auth->post('/logout')->to('auth#logout')->name('admin_logout');
	$auth->get('/')->to( cb => sub { shift->redirect_to('users_index') } );

	# Users — /users/add must come before /users/:user to avoid collision
	$auth->get('/users')->to('users#index')->name('users_index');
	$auth->get('/users/add')->to('users#add')->name('users_add');
	$auth->post('/users')->to('users#create')->name('users_create');
	$auth->get('/users/:user')->to('users#show')->name('users_show');
	$auth->post('/users/:user')->to('users#update')->name('users_update');
	$auth->post('/users/:user/delete')->to('users#delete')->name('users_delete');
	$auth->post('/users/:user/password')->to('users#password')->name('users_password');
	$auth->post('/users/:user/password/remove')->to('users#remove_password')->name('users_remove_password');
	$auth->post('/users/:user/inetorgperson')->to('users#inetorgperson')->name('users_inetorgperson');
	$auth->post('/users/:user/lpk')->to('users#lpk')->name('users_lpk');
	$auth->post('/users/:user/totp')->to('users#totp')->name('users_totp');
	$auth->post('/users/:user/totp/generate')->to('users#totp_generate')->name('users_totp_generate');
	$auth->post('/users/:user/totp/verify')->to('users#totp_verify')->name('users_totp_verify');
	$auth->post('/users/:user/passkeys/enable')->to('users#passkey_enable')->name('users_passkey_enable');
	$auth->post('/users/:user/passkeys/:credentialId/remove')->to('users#passkey_remove')->name('users_passkey_remove');
	$auth->post('/users/:user/groups')->to('users#add_to_group')->name('users_add_to_group');
	$auth->post('/users/:user/groups/:group/remove')->to('users#remove_from_group')->name('users_remove_from_group');

	# Groups — /groups/add and /groups/clean before /groups/:group
	$auth->get('/groups')->to('groups#index')->name('groups_index');
	$auth->get('/groups/add')->to('groups#add')->name('groups_add');
	$auth->post('/groups')->to('groups#create')->name('groups_create');
	$auth->post('/groups/clean')->to('groups#clean')->name('groups_clean');
	$auth->get('/groups/:group')->to('groups#show')->name('groups_show');
	$auth->post('/groups/:group')->to('groups#update')->name('groups_update');
	$auth->post('/groups/:group/delete')->to('groups#delete')->name('groups_delete');
	$auth->post('/groups/:group/members')->to('groups#add_member')->name('groups_add_member');
	$auth->post('/groups/:group/members/:user/delete')->to('groups#remove_member')->name('groups_remove_member');

	# Netgroups — /netgroups/add before /netgroups/:group to avoid collision
	$auth->get('/netgroups')->to('netgroups#index')->name('netgroups_index');
	$auth->get('/netgroups/add')->to('netgroups#add')->name('netgroups_add');
	$auth->post('/netgroups')->to('netgroups#create')->name('netgroups_create');
	$auth->get('/netgroups/:group')->to('netgroups#show')->name('netgroups_show');
	$auth->post('/netgroups/:group')->to('netgroups#update')->name('netgroups_update');
	$auth->post('/netgroups/:group/delete')->to('netgroups#delete')->name('netgroups_delete');

	# OIDC clients — /oidc/add before /oidc/:clientId to avoid collision
	$auth->get('/oidc')->to('o_i_d_c#index')->name('oidc_index');
	$auth->get('/oidc/add')->to('o_i_d_c#add')->name('oidc_add');
	$auth->post('/oidc')->to('o_i_d_c#create')->name('oidc_create');
	$auth->get('/oidc/:clientId')->to('o_i_d_c#show')->name('oidc_show');
	$auth->post('/oidc/:clientId')->to('o_i_d_c#update')->name('oidc_update');
	$auth->post('/oidc/:clientId/delete')->to('o_i_d_c#delete')->name('oidc_delete');
} ## end sub startup

1;
