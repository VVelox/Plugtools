package NisabaTestPlugin;

# A recording App::Nisaba plugin used by t/ldap-plugins.t. App::Nisaba loads
# plugins in-process (string-eval'd `use`), so the test can inspect @CALLS
# afterwards and flip $FAIL to exercise the plugin-error path.

use strict;
use warnings;

our @CALLS;       # one entry per invocation: { do, args, entry_dn, has_self, has_ldap }
our $FAIL = 0;    # when true, report an error back to App::Nisaba

sub plugin {
	my ( $class, $opts, $args ) = @_;

	push @CALLS,
		{
			do       => $opts->{do},
			args     => {%$args},
			entry_dn => ( ref $opts->{entry} ? $opts->{entry}->dn : undef ),
			has_self => ( ref $opts->{self}  ? 1                  : 0 ),
			has_ldap => ( ref $opts->{ldap}  ? 1                  : 0 ),
		};

	my %returned = ( error => undef );
	if ($FAIL) {
		%returned = ( error => 1, errorString => 'forced test failure' );
	}
	return %returned;
} ## end sub plugin

1;
