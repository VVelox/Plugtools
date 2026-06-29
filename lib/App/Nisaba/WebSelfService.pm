package App::Nisaba::WebSelfService;

use Mojo::Base 'Mojolicious', -signatures;
use App::Nisaba;
use File::ShareDir 'dist_dir';

=head1 NAME

App::Nisaba::WebSelfService - Self-service web portal for App::Nisaba

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    # Started via mojo_nisaba_selfservice
    mojo_nisaba_selfservice daemon

=head1 DESCRIPTION

A Mojolicious web application that lets LDAP users change their own
password and manage SSH public keys. Optionally sends password-reset
emails when C<smtpserver> and C<smtpfrom> are configured.

=head1 METHODS

=head2 startup

Mojolicious startup hook. Configures templates, helpers, secret, and
routes.

=cut

sub startup ($self) {
	my $share = dist_dir('App-Nisaba');

	$self->renderer->paths( ["$share/templates"] );
	$self->static->paths( ["$share/public"] );

	# Instantiate App::Nisaba
	my $config_file = $ENV{NISABA_CONFIG};
	my $pt          = App::Nisaba->new( defined($config_file) ? { config => $config_file } : () );

	# Session secret — read from config, fall back to default
	my $default_secret = 'nisaba_change_me';
	my $secret         = $pt->{ini}->{''}->{websecret} // $default_secret;
	$self->secrets( [$secret] );

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

	# Helper: password reset requires SMTP configured AND a non-default secret
	$self->helper(
		reset_available => sub {
			my ($c) = @_;
			return $c->pt->smtpAvailable
				&& ( $c->app->secrets->[0] ne $default_secret );
		}
	);

	# Routes
	my $r = $self->routes;

	# Public routes (no auth required)
	$r->get('/login')->to('self_service#login_form')->name('login');
	$r->post('/login')->to('self_service#login')->name('login_post');
	$r->get('/totp/challenge')->to('self_service#totp_challenge_form')->name('totp_challenge');
	$r->post('/totp/challenge')->to('self_service#totp_challenge')->name('totp_challenge_post');
	$r->get('/forgot')->to('self_service#forgot_form')->name('forgot');
	$r->post('/forgot')->to('self_service#forgot')->name('forgot_post');
	$r->get('/reset/:token')->to('self_service#reset_form')->name('reset');
	$r->post('/reset/:token')->to('self_service#reset')->name('reset_post');
	$r->get('/')->to( cb => sub { shift->redirect_to('dashboard') } );

	# Authenticated routes
	my $auth = $r->under('/')->to('self_service#require_login');
	$auth->get('/dashboard')->to('self_service#dashboard')->name('dashboard');
	$auth->post('/logout')->to('self_service#logout')->name('logout');
	$auth->post('/password')->to('self_service#change_password')->name('change_password');
	$auth->post('/sshkeys/add')->to('self_service#sshkey_add')->name('sshkey_add');
	$auth->post('/sshkeys/remove')->to('self_service#sshkey_remove')->name('sshkey_remove');
	$auth->post('/sshkeys/enable')->to('self_service#sshkey_enable')->name('sshkey_enable');
	$auth->post('/totp/enable')->to('self_service#totp_enable')->name('totp_enable');
	$auth->post('/totp/generate')->to('self_service#totp_generate')->name('totp_generate');
	$auth->post('/totp/verify')->to('self_service#totp_verify')->name('totp_verify');
	$auth->post('/totp/scratch/replace')->to('self_service#totp_scratch_replace')->name('totp_scratch_replace');
	$auth->post('/passkeys/enable')->to('self_service#passkey_enable')->name('passkey_enable');
	$auth->get('/passkeys/register/start')->to('self_service#passkey_register_start')->name('passkey_register_start');
	$auth->post('/passkeys/register/finish')
		->to('self_service#passkey_register_finish')
		->name('passkey_register_finish');
	$auth->post('/passkeys/remove')->to('self_service#passkey_remove')->name('passkey_remove');
	$auth->post('/passkeys/uv')->to('self_service#passkey_uv_set')->name('passkey_uv_set');
} ## end sub startup

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE

Same terms as Perl itself.

=cut

1;
