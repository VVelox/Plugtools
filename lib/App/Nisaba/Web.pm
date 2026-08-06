package App::Nisaba::Web;

use Mojo::Base 'Mojolicious';
use App::Nisaba::WebUtil ();

our $VERSION = '0.0.1';

sub startup {
	my $self = shift;

	# Templates, App::Nisaba instance, session secret and cookie hardening,
	# pt/pt_call helpers, CSRF, rate limiting, and Hypnotoad tuning — shared
	# with the other Nisaba web apps.
	App::Nisaba::WebUtil::install_common_startup( $self, app_description => 'App::Nisaba::Web (admin portal)' );

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

	# OIDC clients — /oidc/add and /oidc/provider-keys before /oidc/:clientId
	# to avoid collision
	$auth->get('/oidc')->to('o_i_d_c#index')->name('oidc_index');
	$auth->get('/oidc/add')->to('o_i_d_c#add')->name('oidc_add');
	$auth->post('/oidc/provider-keys')->to('o_i_d_c#provider_keys')->name('oidc_provider_keys');
	$auth->post('/oidc')->to('o_i_d_c#create')->name('oidc_create');
	$auth->get('/oidc/:clientId')->to('o_i_d_c#show')->name('oidc_show');
	$auth->post('/oidc/:clientId')->to('o_i_d_c#update')->name('oidc_update');
	$auth->post('/oidc/:clientId/delete')->to('o_i_d_c#delete')->name('oidc_delete');
} ## end sub startup

1;
