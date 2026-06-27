package App::Plugtools::Web;

use Mojo::Base 'Mojolicious';
use File::ShareDir qw(dist_dir);
use App::Plugtools;

our $VERSION = '0.0.1';

sub startup {
	my $self = shift;

	# Locate share dir: prefer local ./share for development
	my $share;
	if ( -d 'share' ) {
		$share = 'share';
	} else {
		eval { $share = dist_dir('App-Plugtools') };
		die "Cannot locate share dir (run 'make bootstrap' if not yet done): $@" if $@;
	}
	push @{ $self->renderer->paths }, "$share/templates";
	push @{ $self->static->paths },   "$share/public";

	$self->secrets( [ $ENV{PLUGTOOLS_SECRET} // 'plugtools_change_me_in_production' ] );

	# Shared App::Plugtools instance. Config path via $ENV{PLUGTOOLS_CONFIG} or default.
	$self->helper(
		pt => sub {
			state $pt;
			unless ( defined $pt ) {
				my %args;
				$args{config} = $ENV{PLUGTOOLS_CONFIG} if $ENV{PLUGTOOLS_CONFIG};
				$pt = App::Plugtools->new( \%args );
			}
			return $pt;
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
} ## end sub startup

1;
