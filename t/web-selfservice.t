#!perl
use strict;
use warnings;

use FindBin ();
use lib "$FindBin::Bin/lib";
use NisabaWebTest qw(no_rate_limit);
use Test::More;
use Mojo::Util ();
use Test::Mojo;

eval { require App::Nisaba::WebSelfService };
plan skip_all => "App::Nisaba::WebSelfService failed to load: $@" if $@;

# ── Minimal fake LDAP entry ───────────────────────────────────────────────────
# ── Stateful stubs ────────────────────────────────────────────────────────────

my $current_pw = '{SSHA}ORIGINAL';    # changes when the password is (re)set
my @sent_emails;
my @added_keys;

sub _install_stubs {
	my ($app) = @_;

	my %methods = (
		error       => sub { 0 },
		errorString => sub { '' },
		errorblank  => sub { },

		smtpAvailable => sub { 1 },
		userSelfInfo  => sub { return { mail => 'alice@example.com', totpStatus => 'inactive' } },

		# Password fingerprint source for the single-use reset token.
		getUserEntry    => sub { return FakeEntry->new( userPassword => $current_pw ) },
		userSetPassSelf => sub { my ( $s, $a ) = @_; $current_pw = '{SSHA}NEW-' . $a->{pass}; return 1 },

		sendEmail               => sub { my ( $s, $a ) = @_; push @sent_emails, $a;        return 1 },
		userSSHPublicKeyAddSelf => sub { my ( $s, $a ) = @_; push @added_keys,  $a->{key}; return 1 },

		ldapPublicKeyAvailable => sub { 1 },
		totpSchemaAvailable    => sub { 1 },
		passkeySchemaAvailable => sub { 0 },
		userPasskeyInfoGet     => sub { { hasPasskeyUser => 0, credentials => [] } },
	);

	my $fake = bless { ini => { '' => {} } }, 'FakePT';
	Mojo::Util::monkey_patch( 'FakePT', %methods );
	$app->helper( pt => sub { $fake } );
} ## end sub _install_stubs

my $t = Test::Mojo->new('App::Nisaba::WebSelfService');
_install_stubs( $t->app );

# Same-origin Referer + valid CSRF header on every POST.
$t->ua->on(
	start => sub {
		my ( $ua, $tx ) = @_;
		return unless $tx->req->method eq 'POST';
		my $host = $tx->req->url->to_abs->host_port // 'localhost';
		$tx->req->headers->referrer("http://$host/");
		$tx->req->headers->header( 'X-CSRF-Token' => 'testcsrf' );
	}
);

# Seed the session: a known CSRF token, plus a logged-in user for the
# authenticated SSH-key route.
$t->app->hook( before_dispatch => sub { $_[0]->session( csrf_token => 'testcsrf', user => 'alice' ) } );

# ── Password reset tokens are single use ──────────────────────────────────────

# Request a reset; the token is delivered by email.
@sent_emails = ();
$t->post_ok( '/forgot', form => { user => 'alice' } )->status_is(302);
is( scalar(@sent_emails), 1, 'a reset email was sent' );

my ($token) = ( $sent_emails[0]{body} // '' ) =~ m{/reset/(\S+)};
ok( $token, 'reset email contains a token' );

# First use succeeds and changes the password.
$t->post_ok( "/reset/$token", form => { new_pass => 'newpass1', confirm => 'newpass1' } )
	->status_is(302)
	->header_like( Location => qr{/login}, 'first use of the reset token succeeds' );
is( $current_pw, '{SSHA}NEW-newpass1', 'password was updated by the reset' );

# Reusing the same token now fails: the password changed, so the token's
# signature (bound to the old password fingerprint) no longer validates.
$t->post_ok( "/reset/$token", form => { new_pass => 'evil', confirm => 'evil' } )
	->status_is(302)
	->header_like( Location => qr{/forgot}, 'reused reset token is rejected' );
is( $current_pw, '{SSHA}NEW-newpass1', 'password was NOT changed by the replayed token' );

# ── SSH key add strips all newlines ───────────────────────────────────────────

@added_keys = ();
$t->post_ok( '/sshkeys/add', form => { key => "ssh-rsa AAAAkeydata\r\nMOREdata\n" } )->status_is(302);
is( scalar(@added_keys), 1, 'SSH key add was invoked' );
unlike( $added_keys[0], qr/[\r\n]/, 'all newlines are stripped from the submitted SSH key' );
is( $added_keys[0], 'ssh-rsa AAAAkeydataMOREdata', 'key content is joined into a single line' );

done_testing();
