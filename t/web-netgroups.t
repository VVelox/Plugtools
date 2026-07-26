#!perl
use strict;
use warnings;

use FindBin ();
use lib "$FindBin::Bin/lib";
use NisabaWebTest;

use Test::More;
use Mojo::Util ();
use Test::Mojo;

eval { require App::Nisaba::Web };
if ($@) {
	plan skip_all => "App::Nisaba::Web failed to load: $@";
}

# ── Fake netgroup entries ─────────────────────────────────────────────────────

my $ng_alpha = FakeEntry->new(
	_dn               => 'cn=alpha,ou=netgroup,dc=example,dc=com',
	cn                => 'alpha',
	description       => 'Alpha netgroup',
	nisNetgroupTriple => [ '(host1,user1,example.com)', '(host2,user2,example.com)' ],
	memberNisNetgroup => ['beta'],
);

my $ng_beta = FakeEntry->new(
	_dn               => 'cn=beta,ou=netgroup,dc=example,dc=com',
	cn                => 'beta',
	nisNetgroupTriple => [],
	memberNisNetgroup => [],
);

# ── Stub helper installer ─────────────────────────────────────────────────────

sub _install_stubs {
	my ( $app, %overrides ) = @_;

	my %defaults = (
		error                     => sub { 0 },
		errorString               => sub { '' },
		netgroupbaseConfigured    => sub { 1 },
		oidcbaseConfigured        => sub { 0 },
		getNetgroups              => sub { [ $ng_alpha, $ng_beta ] },
		getNetgroupEntry          => sub { $ng_alpha },
		addNetgroup               => sub { },
		deleteNetgroup            => sub { },
		netgroupDescriptionChange => sub { },
		netgroupTripleAdd         => sub { },
		netgroupTripleRemove      => sub { },
		netgroupMemberAdd         => sub { },
		netgroupMemberRemove      => sub { },
	);

	my %methods = ( %defaults, %overrides );

	my $fake_pt = bless {}, 'FakePT';
	Mojo::Util::monkey_patch( 'FakePT', %methods );

	$app->helper( pt => sub { $fake_pt } );
} ## end sub _install_stubs

# Add a same-host Referer to every POST so the middleware check passes
sub _add_referer_hook {
	my $t = shift;
	$t->ua->on(
		start => sub {
			my ( $ua, $tx ) = @_;
			return unless $tx->req->method eq 'POST';
			my $host = $tx->req->url->to_abs->host_port // 'localhost';
			$tx->req->headers->referrer("http://$host/");
			$tx->req->headers->header( 'X-CSRF-Token' => 'testcsrf' );
		}
	);
} ## end sub _add_referer_hook

my $t = Test::Mojo->new('App::Nisaba::Web');
_install_stubs( $t->app );
_add_referer_hook($t);

# Inject an admin session so routes behind require_login are accessible
$t->app->hook( before_dispatch => sub { $_[0]->session( admin_user => 'testadmin', csrf_token => 'testcsrf' ) } );

# ── index ─────────────────────────────────────────────────────────────────────

$t->get_ok('/netgroups')
	->status_is(200)
	->content_like( qr/alpha/, 'index lists alpha netgroup' )
	->content_like( qr/beta/,  'index lists beta netgroup' );

# index when getNetgroups dies → flash is stored; appears on the next request
_install_stubs( $t->app, getNetgroups => sub { die "LDAP down\n" } );
$t->get_ok('/netgroups')->status_is(200);    # triggers flash, renders empty list
_install_stubs( $t->app );                   # restore working stubs
$t->get_ok('/netgroups')
	->status_is(200)
	->content_like( qr/LDAP down/, 'index shows flash error on subsequent request' );

# ── add (GET) ─────────────────────────────────────────────────────────────────

$t->get_ok('/netgroups/add')->status_is(200)->content_like( qr/Add Netgroup/, 'add form renders' );

# ── create ────────────────────────────────────────────────────────────────────

my $created;
_install_stubs(
	$t->app,
	addNetgroup => sub {
		my ( $self, $args ) = @_;
		$created = $args;
	},
);

$t->post_ok( '/netgroups', form => { group => 'gamma', description => 'Gamma group' } )
	->status_is(302)
	->header_like( Location => qr{/netgroups$}, 'create redirects to index' );
is( $created->{group},       'gamma',       'addNetgroup received correct group name' );
is( $created->{description}, 'Gamma group', 'addNetgroup received description' );

# create failure → redirect back to add
_install_stubs( $t->app, addNetgroup => sub { die "create failed\n" } );
$t->post_ok( '/netgroups', form => { group => 'bad' } )
	->status_is(302)
	->header_like( Location => qr{/netgroups/add}, 'create failure redirects to add form' );
_install_stubs( $t->app );

# ── show ──────────────────────────────────────────────────────────────────────

$t->get_ok('/netgroups/alpha')
	->status_is(200)
	->content_like( qr/alpha/,          'show renders netgroup name' )
	->content_like( qr/Alpha netgroup/, 'show renders description' )
	->content_like( qr/host1,user1/,    'show renders triple' )
	->content_like( qr/beta/,           'show renders member netgroup' );

# show when getNetgroupEntry returns undef → redirect to index
_install_stubs( $t->app, getNetgroupEntry => sub { undef } );
$t->get_ok('/netgroups/missing')
	->status_is(302)
	->header_like( Location => qr{/netgroups$}, 'show redirects to index for unknown netgroup' );
_install_stubs( $t->app );

# ── update: description ───────────────────────────────────────────────────────

my $desc_args;
_install_stubs( $t->app, netgroupDescriptionChange => sub { my ( $self, $args ) = @_; $desc_args = $args }, );
$t->post_ok( '/netgroups/alpha', form => { action => 'description', description => 'New desc' } )
	->status_is(302)
	->header_like( Location => qr{/netgroups/alpha}, 'description update redirects to show' );
is( $desc_args->{description}, 'New desc', 'netgroupDescriptionChange got correct description' );

# ── update: triple_add ────────────────────────────────────────────────────────

my $triple_add_args;
_install_stubs( $t->app, netgroupTripleAdd => sub { my ( $self, $args ) = @_; $triple_add_args = $args }, );
$t->post_ok( '/netgroups/alpha', form => { action => 'triple_add', triple => '(newhost,newuser,example.com)' } )
	->status_is(302);
is( $triple_add_args->{triple}, '(newhost,newuser,example.com)', 'triple_add passes correct triple' );

# ── update: triple_remove ─────────────────────────────────────────────────────

my $triple_rm_args;
_install_stubs( $t->app, netgroupTripleRemove => sub { my ( $self, $args ) = @_; $triple_rm_args = $args }, );
$t->post_ok( '/netgroups/alpha', form => { action => 'triple_remove', triple => '(host1,user1,example.com)' } )
	->status_is(302);
is( $triple_rm_args->{triple}, '(host1,user1,example.com)', 'triple_remove passes correct triple' );

# ── update: member_add ───────────────────────────────────────────────────────

my $member_add_args;
_install_stubs( $t->app, netgroupMemberAdd => sub { my ( $self, $args ) = @_; $member_add_args = $args }, );
$t->post_ok( '/netgroups/alpha', form => { action => 'member_add', member => 'gamma' } )->status_is(302);
is( $member_add_args->{member}, 'gamma', 'member_add passes correct member' );

# ── update: member_remove ────────────────────────────────────────────────────

my $member_rm_args;
_install_stubs( $t->app, netgroupMemberRemove => sub { my ( $self, $args ) = @_; $member_rm_args = $args }, );
$t->post_ok( '/netgroups/alpha', form => { action => 'member_remove', member => 'beta' } )->status_is(302);
is( $member_rm_args->{member}, 'beta', 'member_remove passes correct member' );

# ── update: unknown action ────────────────────────────────────────────────────

_install_stubs( $t->app );
$t->post_ok( '/netgroups/alpha', form => { action => 'bogus' } )
	->status_is(302)
	->header_like( Location => qr{/netgroups/alpha}, 'unknown action redirects to show' );

# ── delete ────────────────────────────────────────────────────────────────────

my $deleted;
_install_stubs( $t->app, deleteNetgroup => sub { my ( $self, $args ) = @_; $deleted = $args->{group} }, );
$t->post_ok('/netgroups/alpha/delete')
	->status_is(302)
	->header_like( Location => qr{/netgroups$}, 'delete redirects to index' );
is( $deleted, 'alpha', 'deleteNetgroup called with correct group name' );

# ── netgroupbase not configured ───────────────────────────────────────────────
# Every route should redirect to groups_index with a flash error.

_install_stubs( $t->app, netgroupbaseConfigured => sub { 0 } );

for my $path (qw( /netgroups /netgroups/add /netgroups/somegroup )) {
	$t->get_ok($path)
		->status_is(302)
		->header_like( Location => qr{/groups$}, "GET $path redirects to groups when unconfigured" );
}

for my $path (qw( /netgroups /netgroups/somegroup /netgroups/somegroup/delete )) {
	$t->post_ok( $path, form => { action => 'description' } )
		->status_is(302)
		->header_like( Location => qr{/groups$}, "POST $path redirects to groups when unconfigured" );
}

_install_stubs( $t->app );

done_testing;
