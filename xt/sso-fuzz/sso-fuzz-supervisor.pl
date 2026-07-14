#!/usr/bin/env perl

# sso-fuzz-supervisor.pl — the crash oracle for the mojo_nisaba_sso fuzz target.
#
# Throwing malformed traffic at the target (with ffuf, wfuzz, Burp, a raw
# fuzzer, ...) is only half of automated breakage detection; something has to
# decide a payload *broke* something. That is this script's job. It:
#
#   1. Picks a free port and launches sso-fuzz-target.pl as a child, merging its
#      STDOUT+STDERR into a log file that is also scanned live.
#   2. Waits for the target to answer OIDC discovery, then prints a READY banner
#      (the URL + creds) so you can point your fuzzer at it.
#   3. Watches, continuously, for breakage:
#        * the target process exiting unexpectedly            (critical)
#        * the health probe failing to connect / non-200      (critical/high)
#        * a health probe that hangs past the latency budget  (high — ReDoS/DoS)
#        * prefork worker deaths / respawns in the log        (high)
#        * Perl exceptions in the log (die, Can't locate, ...) (medium)
#        * runaway resident memory across the process group   (high)
#        * Perl warnings (uninitialised value, ...)           (low)
#   4. On its own SIGINT/SIGTERM (or after --duration), signals the whole target
#      process group, reaps it, and writes a findings report (human summary to
#      STDOUT, machine-readable JSON to --report).
#
# Run this, point your fuzzer at the URL it prints, and read the report.

use strict;
use warnings;

use File::Basename   ();
use File::Spec       ();
use Cwd              ();
use Getopt::Long     qw(:config no_ignore_case bundling);
use IO::Socket::INET ();
use IO::Select       ();
use POSIX            qw(WNOHANG setsid strftime);
use Time::HiRes      qw(time sleep);

$| = 1;    # autoflush STDOUT so findings stream live even when piped to a file

my $SCRIPT_DIR = File::Basename::dirname( Cwd::abs_path(__FILE__) );
my $TARGET     = File::Spec->catfile( $SCRIPT_DIR, 'sso-fuzz-target.pl' );

# ── Options ───────────────────────────────────────────────────────────────────
my %opt = (
	backend          => 'mock',
	host             => '127.0.0.1',
	port             => 0,             # 0 => auto-pick a free port
	workers          => 4,
	'rate-limit'     => 0,
	'log-level'      => 'info',
	'probe-interval' => 2,             # seconds between health probes
	'hang-budget'    => 3.0,           # a probe slower than this is flagged (ReDoS/DoS)
	'mem-limit'      => 0,             # MB across the process group; 0 => no limit
	duration         => 0,             # seconds to run; 0 => until interrupted
	report           => '',            # JSON report path; default derived below
	log              => '',            # target log path; default derived below
);
GetOptions(
	\%opt,         'backend=s',        'host=s',        'port=i',      'workers=i',  'rate-limit=i',
	'log-level=s', 'probe-interval=f', 'hang-budget=f', 'mem-limit=i', 'duration=i', 'report=s',
	'log=s',       'help|h',
) or die "bad options; try --help\n";

if ( $opt{help} ) {
	print <<'USAGE';
usage: sso-fuzz-supervisor.pl [options]

  --backend mock|slapd    target LDAP backend (default: mock)
  --host HOST             bind address (default: 127.0.0.1)
  --port PORT             bind port (default: auto-pick a free port)
  --workers N             target prefork workers (default: 4)
  --rate-limit 0|1        enable the app's rate limiter in the target (default: 0)
  --log-level LEVEL       target Mojo log level (default: info; use debug for traces)
  --probe-interval SECS   health-probe cadence (default: 2)
  --hang-budget SECS      flag probes slower than this (default: 3.0)
  --mem-limit MB          flag if target process-group RSS exceeds this (default: off)
  --duration SECS         stop after this many seconds (default: run until Ctrl-C)
  --report PATH           JSON findings report (default: ./sso-fuzz-report.json)
  --log PATH              target log file (default: ./sso-fuzz-target.log)
  --help

Point your fuzzer at the URL printed once the target is READY.
USAGE
	exit 0;
} ## end if ( $opt{help} )

$opt{report} ||= File::Spec->catfile( Cwd::getcwd(), 'sso-fuzz-report.json' );
$opt{log}    ||= File::Spec->catfile( Cwd::getcwd(), 'sso-fuzz-target.log' );
$opt{port} = _free_port( $opt{host} ) unless $opt{port};

my $BASE = "http://$opt{host}:$opt{port}";

# ── Findings accumulator ──────────────────────────────────────────────────────
# De-duplicated by (severity, category, signature); we keep first/last seen, a
# count, and a sample line.
my %FINDING;
my @FINDING_ORDER;
my %PROBE      = ( ok => 0, fail => 0, slow => 0, min => undef, max => 0, sum => 0 );
my $STARTED_AT = time();

sub record {
	my ( $severity, $category, $signature, $sample ) = @_;
	my $key = "$severity\0$category\0$signature";
	if ( !$FINDING{$key} ) {
		$FINDING{$key} = {
			severity  => $severity,
			category  => $category,
			signature => $signature,
			sample    => $sample,
			count     => 0,
			first     => time(),
			last      => time(),
		};
		push @FINDING_ORDER, $key;
		_say( sprintf '[%s] %-8s %s: %s', _ts(), uc $severity, $category, $signature );
	} ## end if ( !$FINDING{$key} )
	my $f = $FINDING{$key};
	$f->{count}++;
	$f->{last}   = time();
	$f->{sample} = $sample if defined $sample;
	return;
} ## end sub record

# ── Launch the target in its own process group ────────────────────────────────
open my $log_fh, '>', $opt{log} or die "cannot open $opt{log}: $!\n";
$log_fh->autoflush(1);

my @cmd = (
	$^X,            $TARGET,    '--backend', $opt{backend}, '--host',      $opt{host},
	'--port',       $opt{port}, '--workers', $opt{workers}, '--log-level', $opt{'log-level'},
	'--rate-limit', $opt{'rate-limit'},
);

pipe my $rd, my $wr or die "pipe: $!\n";
my $CHILD = fork();
die "fork failed: $!\n" unless defined $CHILD;
if ( $CHILD == 0 ) {
	# Child: new session/pgroup so the supervisor can signal the whole tree
	# (prefork master + workers) at once. Merge STDOUT+STDERR into the pipe.
	setsid();
	close $rd;
	open STDOUT, '>&', $wr or POSIX::_exit(127);
	open STDERR, '>&', $wr or POSIX::_exit(127);
	exec @cmd or POSIX::_exit(127);
}
close $wr;
$rd->blocking(0);

my $CHILD_PGID    = $CHILD;    # setsid() makes the child a group leader: pgid == pid
my $SHUTTING_DOWN = 0;
my $STOPPING      = 0;         # set once we begin teardown: expected worker exits, not crashes
$SIG{INT}  = sub { $SHUTTING_DOWN = 1 };
$SIG{TERM} = sub { $SHUTTING_DOWN = 1 };
$SIG{PIPE} = 'IGNORE';

_say("[$BASE] launching $opt{backend} target (pid $CHILD, log $opt{log})");

# ── Readiness ─────────────────────────────────────────────────────────────────
my $sel            = IO::Select->new($rd);
my $ready          = 0;
my $ready_deadline = time() + ( $opt{backend} eq 'slapd' ? 90 : 30 );
while ( time() < $ready_deadline && !$SHUTTING_DOWN ) {
	_drain_log($sel);
	last if _target_dead();
	my ( $status, $elapsed, $err ) = _probe();
	if ( defined $status && $status == 200 ) { $ready = 1; last }
	sleep 0.3;
}

if ( _target_dead() ) {
	record( 'critical', 'startup', 'target exited before becoming ready', undef );
	_finish();
}
if ( !$ready ) {
	record( 'critical', 'startup', 'target did not answer discovery before timeout', undef );
	_finish();
}

_print_ready_banner();

# ── Watch loop ────────────────────────────────────────────────────────────────
my $end_at     = $opt{duration} ? $STARTED_AT + $opt{duration} : 0;
my $next_probe = time();
my $next_mem   = time();

while ( !$SHUTTING_DOWN ) {
	last if $end_at && time() >= $end_at;

	_drain_log($sel);

	if ( _target_dead() ) {
		record( 'critical', 'process', 'target process exited unexpectedly', undef );
		last;
	}

	if ( time() >= $next_probe ) {
		$next_probe = time() + $opt{'probe-interval'};
		my ( $status, $elapsed, $err ) = _probe();
		if ( !defined $status ) {
			$PROBE{fail}++;
			record( 'critical', 'liveness', "health probe failed: $err", undef );
		} else {
			_probe_stats($elapsed);
			if ( $status != 200 ) {
				$PROBE{fail}++;
				record( 'high', 'liveness', "discovery returned HTTP $status", undef );
			} elsif ( $elapsed > $opt{'hang-budget'} ) {
				$PROBE{slow}++;
				record(
					'high', 'dos',
					sprintf(
						'discovery took %.2fs (> %.2fs budget) — possible ReDoS/DoS',
						$elapsed, $opt{'hang-budget'}
					),
					undef
				);
			} else {
				$PROBE{ok}++;
			}
		} ## end else [ if ( !defined $status ) ]
	} ## end if ( time() >= $next_probe )

	if ( $opt{'mem-limit'} && time() >= $next_mem ) {
		$next_mem = time() + 5;
		my $rss = _group_rss_mb();
		if ( defined $rss && $rss > $opt{'mem-limit'} ) {
			record( 'high', 'memory', sprintf( 'process-group RSS %d MB exceeds %d MB limit', $rss, $opt{'mem-limit'} ),
				undef );
		}
	}

	select undef, undef, undef, 0.2;    ## no critic (ProhibitSleepViaSelect)
} ## end while ( !$SHUTTING_DOWN )

_finish();

# ── Log scanning ──────────────────────────────────────────────────────────────
my $LOG_BUF = '';

sub _drain_log {
	my ($select) = @_;
	return unless $select->can_read(0);
	my $chunk;
	my $n = sysread $rd, $chunk, 65_536;
	return unless $n;    # 0 == EOF, undef == would-block/err
	print {$log_fh} $chunk;
	$LOG_BUF .= $chunk;
	while ( $LOG_BUF =~ s/\A([^\n]*)\n// ) {
		_scan_line($1);
	}
	return;
} ## end sub _drain_log

sub _scan_line {
	my ($line) = @_;
	return if $line eq '';

	# Once we are tearing the target down, prefork logs expected worker/manager
	# stops; do not misreport those as crashes.
	return if $STOPPING;

	# prefork worker lifecycle — an unexpected worker exit is a crash signal.
	if ( $line =~ /worker\s+(\d+)\s+(?:stopped|exited)/i ) {
		record( 'high', 'worker', 'prefork worker stopped/exited (possible crash)', $line );
		return;
	}

	# Hard Perl runtime failures.
	if ( $line
		=~ /(Can't locate\b|Can't call method\b|Undefined subroutine\b|Not a (?:HASH|ARRAY|CODE|SCALAR) reference|Modification of a read-only value|Can't use (?:an undefined value|string)|Deep recursion|panic:|Out of memory|DBD::\w+|database is locked|disk I\/O error|Can't contact LDAP|died\b)/
		)
	{
		my $sig = $1;
		record( 'medium', 'exception', "Perl/runtime error: $sig", $line );
		return;
	}

	# Mojolicious logs the message of a caught action exception at error level.
	if ( $line =~ /\[error\]/ ) {
		record( 'medium', 'app-error', 'app logged an error', $line );
		return;
	}

	# Warnings — noisy but occasionally the first sign of a bad code path.
	if ( $line
		=~ /(Use of uninitialized value|Wide character|Argument .* isn't numeric|substr outside of string|Deep recursion)/
		)
	{
		record( 'low', 'warning', $1, $line );
		return;
	}
	return;
} ## end sub _scan_line

# ── Health probe (raw HTTP so we control connect/read timeouts) ───────────────
sub _probe {
	my $path = '/.well-known/openid-configuration';
	my $t0   = time();
	my $sock = IO::Socket::INET->new(
		PeerAddr => $opt{host},
		PeerPort => $opt{port},
		Proto    => 'tcp',
		Timeout  => $opt{'hang-budget'},
	);
	return ( undef, 0, "connect: $!" ) unless $sock;

	my $req = "GET $path HTTP/1.0\r\nHost: $opt{host}:$opt{port}\r\nConnection: close\r\n\r\n";
	{
		local $SIG{ALRM} = sub { die "timeout\n" };
		my $status = eval {
			alarm( int( $opt{'hang-budget'} ) + 1 );
			print {$sock} $req;
			my $first = <$sock>;
			alarm 0;
			$first;
		};
		alarm 0;
		close $sock;
		if ( !defined $status ) { return ( undef, time() - $t0, 'read timeout/hang' ) }
		my ($code) = $status =~ m{\AHTTP/\d\.\d\s+(\d{3})};
		return ( $code // 0, time() - $t0, undef );
	}
} ## end sub _probe

sub _probe_stats {
	my ($elapsed) = @_;
	$PROBE{min} = $elapsed if !defined $PROBE{min} || $elapsed < $PROBE{min};
	$PROBE{max} = $elapsed if $elapsed > $PROBE{max};
	$PROBE{sum} += $elapsed;
	return;
}

# ── Process helpers ───────────────────────────────────────────────────────────
sub _target_dead {
	my $r = waitpid $CHILD, WNOHANG;
	return $r == $CHILD || $r == -1;
}

# Sum RSS (MB) of every process in the target's group via /proc.
sub _group_rss_mb {
	return undef unless -d '/proc';
	my $total = 0;
	opendir my $dh, '/proc' or return undef;
	for my $pid ( grep { /\A\d+\z/ } readdir $dh ) {
		open my $sfh, '<', "/proc/$pid/stat" or next;
		my $line = <$sfh>;
		close $sfh;
		next unless defined $line;
		# fields: pid (comm) state ppid pgrp ...
		next unless $line =~ /\A\d+\s+\([^)]*\)\s+\S+\s+\d+\s+(\d+)/;
		next unless $1 == $CHILD_PGID;
		if ( open my $rfh, '<', "/proc/$pid/status" ) {
			while ( my $l = <$rfh> ) {
				if ( $l =~ /\AVmRSS:\s+(\d+)\s+kB/ ) { $total += $1; last }
			}
			close $rfh;
		}
	} ## end for my $pid ( grep { /\A\d+\z/ } readdir $dh)
	closedir $dh;
	return int( $total / 1024 );
} ## end sub _group_rss_mb

sub _free_port {
	my ($host) = @_;
	my $s = IO::Socket::INET->new( LocalAddr => $host, Proto => 'tcp', Listen => 1 )
		or die "cannot allocate a local port: $!\n";
	my $port = $s->sockport;
	close $s;
	return $port;
}

# ── Shutdown + report ─────────────────────────────────────────────────────────
sub _finish {
	$STOPPING = 1;
	_say('[shutdown] stopping target...');
	if ( !_target_dead() ) {
		kill 'TERM', -$CHILD_PGID;
		my $deadline = time() + 8;
		while ( time() < $deadline ) {
			last if _target_dead();
			sleep 0.2;
		}
		kill 'KILL', -$CHILD_PGID if !_target_dead();
		waitpid $CHILD, 0;
	} ## end if ( !_target_dead() )

	# Drain anything still buffered from the target.
	_drain_log($sel) for 1 .. 3;
	close $log_fh;

	_write_report();
	_print_summary();
	my $criticals = grep { $FINDING{$_}{severity} eq 'critical' } @FINDING_ORDER;
	exit( $criticals ? 2 : ( @FINDING_ORDER ? 1 : 0 ) );
} ## end sub _finish

sub _write_report {
	require Mojo::JSON;
	my @findings = map {
		my $f = $FINDING{$_};
		{
			severity   => $f->{severity},
			category   => $f->{category},
			signature  => $f->{signature},
			count      => $f->{count},
			sample     => $f->{sample},
			first_seen => strftime( '%Y-%m-%dT%H:%M:%S', localtime int $f->{first} ),
			last_seen  => strftime( '%Y-%m-%dT%H:%M:%S', localtime int $f->{last} ),
		}
	} @FINDING_ORDER;

	my $probe_avg = $PROBE{ok} + $PROBE{slow} ? $PROBE{sum} / ( $PROBE{ok} + $PROBE{slow} ) : 0;
	my $report    = {
		target     => $BASE,
		backend    => $opt{backend},
		workers    => $opt{workers},
		rate_limit => $opt{'rate-limit'} ? \1 : \0,
		duration_s => sprintf( '%.1f', time() - $STARTED_AT ),
		log        => $opt{log},
		probe      => {
			ok            => $PROBE{ok},
			slow          => $PROBE{slow},
			fail          => $PROBE{fail},
			latency_min_s => defined $PROBE{min} ? sprintf( '%.4f', $PROBE{min} ) : undef,
			latency_avg_s => sprintf( '%.4f', $probe_avg ),
			latency_max_s => sprintf( '%.4f', $PROBE{max} ),
		},
		findings => \@findings,
	};
	if ( open my $fh, '>', $opt{report} ) {
		print {$fh} Mojo::JSON::encode_json($report);
		close $fh;
	}
	return;
} ## end sub _write_report

sub _print_summary {
	my %by_sev;
	$by_sev{ $FINDING{$_}{severity} }++ for @FINDING_ORDER;
	_say('');
	_say('══════════════════════════ sso-fuzz summary ══════════════════════════');
	_say( sprintf ' target %s  (%s backend, %.0fs)', $BASE, $opt{backend}, time() - $STARTED_AT );
	_say(
		sprintf ' probes ok=%d slow=%d fail=%d  latency avg=%.3fs max=%.3fs',
		$PROBE{ok}, $PROBE{slow}, $PROBE{fail},
		( $PROBE{ok} + $PROBE{slow} ? $PROBE{sum} / ( $PROBE{ok} + $PROBE{slow} ) : 0 ),
		$PROBE{max}
	);
	if (@FINDING_ORDER) {
		_say( sprintf ' findings: %s',
			join ', ', map { "$_=$by_sev{$_}" } grep { $by_sev{$_} } qw(critical high medium low) );
		for my $sev (qw(critical high medium low)) {
			for my $key ( grep { $FINDING{$_}{severity} eq $sev } @FINDING_ORDER ) {
				my $f = $FINDING{$key};
				_say( sprintf '  [%-8s] %-10s x%-4d %s', uc $sev, $f->{category}, $f->{count}, $f->{signature} );
			}
		}
	} else {
		_say(' findings: none — no breakage observed');
	}
	_say(" report:  $opt{report}");
	_say(" log:     $opt{log}");
	_say('═══════════════════════════════════════════════════════════════════════');
	return;
} ## end sub _print_summary

sub _print_ready_banner {
	_say('');
	_say("  READY — point your fuzzer at:  $BASE");
	_say("  discovery:  $BASE/.well-known/openid-configuration");
	_say('  (credentials are in the target banner above; Ctrl-C to stop and report)');
	_say('');
	return;
}

sub _ts  { return strftime( '%H:%M:%S', localtime ) }
sub _say { my ($m) = @_; print {*STDOUT} "$m\n"; return }
