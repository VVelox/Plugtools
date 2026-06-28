package App::Nisaba::Web;

use Mojo::Base 'Mojolicious';
use File::ShareDir qw(dist_dir);
use App::Nisaba;
use Mojo::URL;

our $VERSION = '0.0.1';

sub startup {
	my $self = shift;

	my $share = dist_dir('App-Nisaba');
	push @{ $self->renderer->paths }, "$share/templates";
	push @{ $self->static->paths },   "$share/public";

	$self->secrets( [ $ENV{NISABA_SECRET} // 'nisaba_change_me_in_production' ] );

	# Shared App::Nisaba instance. Config path via $ENV{NISABA_CONFIG} or default.
	$self->helper(
		pt => sub {
			state $pt;
			unless ( defined $pt ) {
				my %args;
				$args{config} = $ENV{NISABA_CONFIG} if $ENV{NISABA_CONFIG};
				$pt = App::Nisaba->new( \%args );
			}
			return $pt;
		}
	);

	# Referer check: every POST must originate from the same host.
	$self->hook(
		before_dispatch => sub {
			my $c = shift;
			return unless $c->req->method eq 'POST';

			my $referer = $c->req->headers->referrer;
			unless ($referer) {
				$c->render( text => 'Forbidden: missing Referer header', status => 403 );
				return;
			}

			my $ref_host = Mojo::URL->new($referer)->host // '';
			my $req_host = $c->req->url->to_abs->host     // '';
			unless ( $ref_host eq $req_host ) {
				$c->render( text => 'Forbidden: Referer host mismatch', status => 403 );
				return;
			}
		}
	);

	my $r = $self->routes;

	$r->get('/')->to( cb => sub { shift->redirect_to('users_index') } );

	# Users — /users/add must come before /users/:user to avoid collision
	$r->get('/users')->to('users#index')->name('users_index');
	$r->get('/users/add')->to('users#add')->name('users_add');
	$r->post('/users')->to('users#create')->name('users_create');
	$r->get('/users/:user')->to('users#show')->name('users_show');
	$r->post('/users/:user')->to('users#update')->name('users_update');
	$r->post('/users/:user/delete')->to('users#delete')->name('users_delete');
	$r->post('/users/:user/password')->to('users#password')->name('users_password');
	$r->post('/users/:user/password/remove')->to('users#remove_password')->name('users_remove_password');
	$r->post('/users/:user/inetorgperson')->to('users#inetorgperson')->name('users_inetorgperson');
	$r->post('/users/:user/lpk')->to('users#lpk')->name('users_lpk');
	$r->post('/users/:user/groups')->to('users#add_to_group')->name('users_add_to_group');
	$r->post('/users/:user/groups/:group/remove')->to('users#remove_from_group')->name('users_remove_from_group');

	# Groups — /groups/add and /groups/clean before /groups/:group
	$r->get('/groups')->to('groups#index')->name('groups_index');
	$r->get('/groups/add')->to('groups#add')->name('groups_add');
	$r->post('/groups')->to('groups#create')->name('groups_create');
	$r->post('/groups/clean')->to('groups#clean')->name('groups_clean');
	$r->get('/groups/:group')->to('groups#show')->name('groups_show');
	$r->post('/groups/:group')->to('groups#update')->name('groups_update');
	$r->post('/groups/:group/delete')->to('groups#delete')->name('groups_delete');
	$r->post('/groups/:group/members')->to('groups#add_member')->name('groups_add_member');
	$r->post('/groups/:group/members/:user/delete')->to('groups#remove_member')->name('groups_remove_member');

	# Netgroups — /netgroups/add before /netgroups/:group to avoid collision
	$r->get('/netgroups')->to('netgroups#index')->name('netgroups_index');
	$r->get('/netgroups/add')->to('netgroups#add')->name('netgroups_add');
	$r->post('/netgroups')->to('netgroups#create')->name('netgroups_create');
	$r->get('/netgroups/:group')->to('netgroups#show')->name('netgroups_show');
	$r->post('/netgroups/:group')->to('netgroups#update')->name('netgroups_update');
	$r->post('/netgroups/:group/delete')->to('netgroups#delete')->name('netgroups_delete');
} ## end sub startup

1;
