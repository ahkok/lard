#!/usr/bin/perl 
#
# $Id: syslog-snarf,v 2.1 2004/06/08 07:50:44 jmates Exp $
#
# The author disclaims all copyrights and releases this document into
# the public domain.
#
# Simple syslogd server for debugging or experimenting with syslog.
#
# Run perldoc(1) on this file for additional documentation.

use strict;

use Socket;
use IO::Socket;
use IO::Select;

use Sys::Syslog;
use Net::Syslog;

use Sys::Hostname;

use Getopt::Std;
use Date::Parse;
use POSIX qw(strftime);

# what address to listen on (default everywhere)
my $bind;

# what port to bind to by default
my $port = 514;

# max message length for incoming data ([RFC 3164] limits this to 1024
# by default, though things might not follow the standards)
my $max_msg_len	= 5000;
my $msg_len_warn = 1024;

use vars qw(@rules %option %opts $PRI_data_re $HEADER_MSG_re_syslog_ng);


# to match PRI header plus remaining fields
my $PRI_data_re = qr/^ < (\d{1,3}) > (.*) /x;

# to decode remaining data past the priority into TIMESTAMP, HOSTNAME,
# and MSG fields
my $HEADER_MSG_re_syslog_ng = qr/^ ((	# match HEADER, TIMESTAMP for reference
	(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)	# Month
	(?:[ ][ ]\d|[ ]\d\d) # day of month, '	5' or ' 10'
	[ ] \d\d:\d\d:\d\d)	 # timestamp
	[ ] ([\w@.:-]+)      # HOSTNAME host|IPv4|IPv6 (syslog-ng prefixes foo@?)
	)                    # close match on HEADER
	[ ] (.*)             # MSG data
/x;
my $HEADER_MSG_re_solaris = qr/^ ((
	(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)	# Month
	(?:[ ][ ]\d|[ ]\d\d) # day of month, '	5' or ' 10'
	[ ] \d\d:\d\d:\d\d)  # timestamp
	)                    # close match on HEADER
	[ ] (.*)             # MSG data
/x;

# see strftime man page for allowed fields here
my $timestamp_template = "%Y-%m-%d %H:%M:%S%z";

# this is a custom template based on contents of %message hash for each
# log entry
my $message_template =
 '%{TIMESTAMP} <%{facility}.%{priority}> %{HOSTNAME} %{MSG}\n';

# syslog.h code->name mappings for better output
my %syslog_priorities = (
	0 => 'emerg',
	1 => 'alert',
	2 => 'crit',
	3 => 'err',
	4 => 'warning',
	5 => 'notice',
	6 => 'info',
	7 => 'debug'
);
my $pri_mask_full = ((2<<8) - 2);

# TODO some vendors (notably Apple) have fiddled with these to add
# NETINFO and similar... support this by reading these defintions
# from a file?
my %syslog_facilities = (
	0  => 'kern',
	1  => 'user',
	2  => 'mail',
	3  => 'daemon',
	4  => 'auth',
	5  => 'syslog',
	6  => 'lpr',
	7  => 'news',
	8  => 'uucp',
	9  => 'cron',
	10 => 'authpriv',
	11 => 'ftp',
	16 => 'local0',
	17 => 'local1',
	18 => 'local2',
	19 => 'local3',
	20 => 'local4',
	21 => 'local5',
	22 => 'local6',
	23 => 'local7'
);

my $fac_mask_full = ((2<<24) - 2);

my %syslog_facilities_rv;
my %syslog_priorities_rv;
# generate reverse hashes for speedy lookups
for my $key (keys %syslog_facilities) {
	$syslog_facilities_rv{$syslog_facilities{$key}} = $key;
}
for my $key (keys %syslog_priorities) {
	$syslog_priorities_rv{$syslog_priorities{$key}} = $key;
}

my $VERSION;
( $VERSION = '$Revision: 2.1 $ ' ) =~ s/[^0-9.]//g;

# parse command-line options
getopts 'h?lnvb:p:', \%opts;

print_help() if exists $opts{'h'} or exists $opts{'?'};

# list known elements might be in %message for templating needs
if ( $opts{'l'} ) {
	print join(
		"\n",
		qw{raw MSG time_recv TIME TIMESTAMP priority length HOSTNAME facility facility_code peerport HEADER priority_code peerhost PRI}
	 ),
		"\n";
	exit;
}

&parse_config();

for my $rule (@rules) {
	for my $key (keys %{$rule}) {
		print "$key => ${$rule}{$key}\n";
	}
	print "\n";
}

# no input checking as let IO::Socket handle any errors
my (@bind) = ( 'LocalAddr', $opts{'b'} ) if exists $opts{'b'};
$port = $opts{'p'} if exists $opts{'p'};

##$SIG{'INT'} = sub { exit 0 };	# control+c handler

# start up the syslog server

# listen on the UDP socket
my $sock1 = IO::Socket::INET->new(
	Proto     => 'udp',
	LocalPort => $port,
	@bind
 )
 or die "error: could not start server: errno=$@\n";
# listen on '/dev/log' socket
unlink '/dev/log';
my $sock2 = IO::Socket::UNIX->new(
	Local   => "/dev/log",
	Type    => SOCK_DGRAM,
	Listen  => 0
 )
 or die "error: could not start server: errno=$@\n";
chmod 0666, '/dev/log';

$| = 1;												# autoflush output

#nonblock($sock1);
#nonblock($sock2);

my $select = IO::Select->new();
$select->add($sock1);
$select->add($sock2);

# and add the signal hook:
$SIG{'USR2'} = \&catch_rotate_signal;
$SIG{'TERM'} = \&end;
$SIG{'HUP'} = \&end;

# fork into the background unless we don't want that
my $pid;
($opts{'n'}) or ($pid = fork and exit);

# send out a syslog.notice that we have just started
send_local ('notice', 'started');

&read_messages;

sub read_messages {
	# handle messages as usual
	while (my @ready = $select->can_read) {
		foreach my $sock (@ready) {
			handle ($sock);
		}
	}
}

# add signal handler to trigger rotation
sub catch_rotate_signal {
	send_local ("notice", "Received rotation request signal (USR2)");
	rotate_all();

	sleep(5);
	
	&read_messages();
}

sub end {
	# send out a syslog.notice that we are exiting, but only for
	($pid) or send_local ( 'notice', 'shuting down...');
	$sock1->close if $sock1;
	$sock2->close if $sock2;
}

END {
	end;
}

sub send_local {
	# send a message to ourselves locally, so it can be parsed and passed
	# through our ruleset
	( my $id = $0 ) =~ s/^.*\/// ;
	openlog($id, 'pid', 'syslog');
	syslog(shift, shift);
	closelog();
}


sub send_remote {
	# send a message to a specific loghost
	my $host = shift;
	my %message = %{ shift() };

	my $syslog = new Net::Syslog (
			SyslogHost => $host,
			Facility => $message{'facility'},
			Priority => $message{'priority'}
		);
	$syslog->send("$message{'MSG'}\n");
}


sub unquote {
	# remove "" quotes from a string
	my $word = shift;
	$word =~ s/^"(.*)"$/$1/;
	return $word;
}


sub format_message {
	my $template = shift;
	my %message = %{ shift() };
	
	# converts '\n' and similar to actual character
	( my $output = $template ) =~ s/(\\.)/qq!"$1"!/eeg;

	# replaces %{foo} keys from %message hash with values for log entry
	$output =~ s/%{(\w+)}/$message{$1}||''/eg;
	return $output;
}


sub parse_config {
	my @words;

	# read and parse rules from the config file
	local *CONF;
	open(CONF, "/etc/logd.conf");
	while (<CONF>) {
		s/#.*$//g;
		for (m/(\x22[^\x22]+\x22|\x27[^\x27]+\x27|\x60[^\x60]+\x60|[0-9a-zA-Z\x21\x23-\x26\x2a-\x3a\x3c-\x7a\x7c\x7e\x7f]+|\x28|\x29|\x7b|\x7d|\x3b)/g) {
			push @words, $_;
		}
	}
	close (CONF);

	my %rule;
	undef %rule;
	# while ($word = shift @words) {
	while ( local $_ = shift @words ) {
		/^(?:file|pipe|command|host)$/ && do {
			if (%rule) {
				# store last rule if it exists
				push @rules, {%rule};
				undef %rule;
			}
			# create a new rule
			$rule{$_} = unquote ( shift @words );
			next;
		};
		/^(?:log|timeformat|format|keep|rotate|compress|match)$/ && do {
			if (! %rule) {
				$option{$_} = unquote ( shift @words );
			} else {
				# global options
				$rule{$_} = unquote ( shift @words );
				# create binary mask for facility.priority
				/^log$/ && do {
					# set the default mask to full
					my ( $fac, $pri ) = split ( /\./, $rule{$_} );
					# facility
					if ( $fac eq '*' ) {
						$rule{'fac_mask'} = $fac_mask_full;
					} else {
						for my $fac_item ( split ( /\,/, $fac ) ) {
							# if negated, deduct the prio from the mask
							if ( substr($fac_item, 0, 1) eq '!' ) {
								$rule{'fac_mask'} &= ( $fac_mask_full - ( 2<<$syslog_facilities_rv{substr($fac_item, 1)} ) );
							} else {
								# else add it to it
								$rule{'fac_mask'} |= ( 2<<$syslog_facilities_rv{$fac_item} );
							}
						}
					}
					# priority
					if ( $pri eq '*' ) {
						$rule{'pri_mask'} = $pri_mask_full;
					} else {
						for my $pri_item ( split ( /,/, $pri ) ) {
							# if negated, deduct the prio from the mask
							if ( substr($pri_item, 0, 1) eq '!' ) {
								if ( ! defined $rule{'pri_mask'} ) {
									$rule{'pri_mask'} = $pri_mask_full;
								}
								$rule{'pri_mask'} &= ( $pri_mask_full - ( 2<<$syslog_priorities_rv{substr($pri_item, 1)} ) );
							} else {
								# else add it to it
								$rule{'pri_mask'} |= ( 2<<$syslog_priorities_rv{$pri_item} );
							}
						}
					}
				}
			}
			next;
		}
	}

	# add the last rule in case it's there
	if (%rule) {
		push @rules, {%rule};
	}
}

sub rotate_all {
	# check to see if we can rotate logfiles now
	my ($keep, $rotate, $compress);
	for my $rule (@rules) {
		if ((${$rule}{'file'}) && (${$rule}{'file'} ne "-")) {
			# it's a logfile rule -> recover the rotation params
			if (${$rule}{'keep'}) {
				$keep = ${$rule}{'keep'};
			} elsif ($option{'keep'}) {
				$keep = $option{'keep'};
			} else {
				$keep = 4;
			}
			if (${$rule}{'rotate'}) {
				$rotate = ${$rule}{'rotate'};
			} elsif ($option{'rotate'}) {
				$rotate = $option{'rotate'};
			} else {
				$rotate = "weekly";
			}
			if (${$rule}{'compress'}) {
				$compress = ${$rule}{'compress'};
			} elsif ($option{'compress'}) {
				$compress = $option{'compress'};
			} else {
				$compress = "none";
			}
			print "${$rule}{'file'}: $keep, $rotate, $compress\n";

#			rotate_file(${$rule}{'file'}, $keep, $compress);
		}
	}
}

sub rotate_file {
	# takes a filename as argument #1
	# numer of rotations as #2
	# compression method as #3
	my $file = shift;
	my $keep = shift;
	my $compress = shift;

	my $suffix;
	if ($compress eq "bzip2") {
		$suffix = ".bz2";
	} elsif ($compress eq "gzip") {
		$suffix = ".gz";
	}

	for ( my $num = $keep; $num > 0 ; $num-- ) {
		# move old files up
		if ( -f "$file." . $num . "$suffix" ) {
			if ($num == $keep) {
				# delete the oldes if it's the last one to keep
				unlink "$file." . $num . "$suffix";
			} else {
				# move them up
				rename "$file." . $num . "$suffix", "$file." . ($num+1) . "$suffix";
			}
		}
	}
	# now move the current one
	if ( -f "$file" ) {
		rename "$file", "$file.1";
		# and compress it
		if (( $compress ne "none" ) && (fork == 0)) {
			exec("$compress $file.1");
		}
	}
}

# this is the incoming message handler
sub handle {
	my $sock = shift;
	my ( %message, @errors );
	
	%message = ();
	@errors	= ();

	$sock->recv( $message{'raw'}, $max_msg_len );

	$message{'time_recv'} = time;
	
	# distonguish based on the protocol
	if ( $sock->sockdomain == AF_INET ) {
		# get various info on the packet in question
		$message{'peerhost'} = gethostbyaddr( $sock->peeraddr, AF_INET )
		 || $sock->peerhost;
		$message{'peerport'} = $sock->peerport;
	} else {
		# log with local name
		$message{'peerhost'} = hostname();
	}

	# see [RFC 3164] for syslog message format details
	$message{'length'} = length( $message{'raw'} );
	push @errors, "message exceeds length of $msg_len_warn"
	 if $message{'length'} > $msg_len_warn;

	if ( $message{'length'} == 0 ) {
		push @errors, 'message contains no data';
		next;
	}

	my $header_msg = '';

	if ( $message{'raw'} =~ m/$PRI_data_re/o ) {
		( $message{'PRI'}, $header_msg ) = ( $1, $2 );

		# decode facility/priority (see [RFC 2234] for PRI part values
		if ( $message{'PRI'} ) {
			$message{'priority_code'} = $message{'PRI'} % 8;
			if ( exists $syslog_priorities{ $message{'priority_code'} } ) {
				$message{'priority'} = $message{'priority_code'};
				$message{'priority'} = $syslog_priorities{ $message{'priority_code'} };
			} else {
				push @errors, "no name for priority $message{'priority_code'}";
			}

			$message{'facility_code'} = int( $message{'PRI'} / 8 );
			if ( exists $syslog_facilities{ $message{'facility_code'} } ) {
				$message{'facility'} = $syslog_facilities{ $message{'facility_code'} };
			} else {
				$message{'facility'} = $message{'facility_code'};
				push @errors, "no name for facility $message{'facility_code'}";
			}
		}

	} else {
		push @errors, 'could not parse PRI field';
		next;
	}

	# TODO is syslog-ng adding \n to the data already?
	chomp $header_msg;
	if ( $header_msg =~ m/$HEADER_MSG_re_syslog_ng/o ) {
		(
			$message{'HEADER'},	 $message{'TIME'},
			$message{'HOSTNAME'}, $message{'MSG'}
		)
		 = ( $1, str2time ($2), $3, $4 );
	} elsif ( $header_msg =~ m/$HEADER_MSG_re_solaris/o ) {
		(
		 $message{'HEADER'},	 $message{'TIME'},
		 $message{'HOSTNAME'}, $message{'MSG'}
		)
		 = ( $1, str2time ($2), $message{'peerhost'}, $3 );
		# solaris' syslogd passes the fac.pri tuple, get rid if it:
		$message{'MSG'} =~ s/ $message{'facility'}\.$message{'priority'}// ;
	} else {
		(
		 $message{'HEADER'},	 $message{'TIME'},
		 $message{'HOSTNAME'}, $message{'MSG'}
		)
		 = ( '', time , $message{'peerhost'}, $header_msg );
	}
	( $message{'HOSTNAME'}, my $junk ) = split ( /\./, $message{'HOSTNAME'} );

	if ( $opts{v} and @errors ) {
		warn "error: $_\n" for @errors;
	}

	# here we traverse our logging rules and apply the proper procedure
	# (multiple actions possible)
	for my $rule (@rules) {
		# perform a match on $message{'facility|priority'}
		if ( ( ${$rule}{'pri_mask'} & ( 2<<$message{'priority_code'}) ) &&
				( ${$rule}{'fac_mask'} & ( 2<<$message{'facility_code'}) ) ) {
			# create the output format message now
			my $output;
			# figure out what timestamp format we need
			if ( defined ${$rule}{'timeformat'} ) {
				$message{'TIMESTAMP'} = strftime ${$rule}{'timeformat'}, localtime ($message{'TIME'});
			} elsif ( defined $option{'timeformat'} ) {
				$message{'TIMESTAMP'} = strftime $option{'timeformat'}, localtime ($message{'TIME'});
			} else {
				$message{'TIMESTAMP'} = strftime $timestamp_template, localtime ($message{'TIME'});
			}
			if ( defined ${$rule}{'format'} ) {
				$output = format_message ( ${$rule}{'format'}, \%message );
			} elsif ( defined $option{'format'} ) {
				$output = format_message ( $option{'format'}, \%message );
			} else {
				$output = format_message ( $message_template, \%message );
			}
			# complex match so we can match hostname/time too:
			for ($output) {
				# seach for a pattern if applicable
				if ( (! defined ${$rule}{'match'} ) || 
						( m/${$rule}{'match'}/ ) ) {
					if (defined ${$rule}{'file'}) {
						# append the message to this file
						if ( ${$rule}{'file'} eq "-" ) {
							print $output;
						} else {
							# very bad writing below
							local *LOG;
							open ( LOG, ">>${$rule}{'file'}" );
							print LOG $output;
							close ( LOG );
						}
					} elsif (defined ${$rule}{'pipe'}) {
						# write to a pipe

					} elsif (defined ${$rule}{'command'}) {
						# execute a command
						chomp $output;
						if (fork == 0) {
							# $SIG{CHLD} = 'IGN' || waitpid(-1, WNOHANG)
							exec("${rule}{'command'} \'$output\'");
						}
					} elsif (defined ${$rule}{'host'}) {
						# log to a remote host
						send_remote ( ${$rule}{'host'}, \%message );
					}
				}
			}
		}
	}
}


# a generic help blarb
sub print_help {
	print <<"HELP";
Usage: $0 [opts]

Simple syslogd server for debugging or experimenting with syslog.

Options for version $VERSION:
	-h/-?	Display this message
	-l		 Lists available message keys to template on and exists

	-v		 Verbose: lists errors in parsing log data

	-b bb	Bind to host or address instead of to everything
	-p pp	Use UDP port instead of default ($port)

	-n		 Do not fork into the background

Run perldoc(1) on this script for additional documentation.

HELP
	exit 100;
}

=head1 NAME

syslog-snarf - Simple syslogd server for debugging syslog

=head1 SYNOPSIS

Close any running syslog daemon (the stock syslogd binds to UDP port 514
even when not being a server), then run the following to act as a
debugging syslog server:

	# syslog-snarf

Bind to an alternate localhost-only port, be verbose about errors, and
use custom time and message formats:

	$ syslog-snarf -b 127.1 -p 9999 -v -t %s -f '%{time_recv} %{raw}\n'

To see a list of available message fields for templating:

	$ syslog-snarf -l

=head1 DESCRIPTION

This script is a simple syslog server that binds to a specified UDP
port (514 by default) and prints out a formatted message of the
parsed log data:

	2004-06-08T00:16:48-0700 <user.notice> example.org username: test

The output format of the log entries and the timestamps involved can be
altered via templates; timestamps use strftime(3) templates, and log
entries a custom macro format that uses C<%{keyword}> expansion. The
currently supported keys to expand on are:

	HEADER - syslog message data past the priority field
	HOSTNAME
	MSG
	PRI - syslog protocol facility/priority number
	TIMESTAMP - timestamp set by log generator
	facility
	facility_code
	length - size of log packet
	peerhost - where log packet came from
	peerport
	priority
	priority_code
	raw - unparsed log data
	time_recv - timestamp when log entry seen by this script
	
=head2 Normal Usage

	$ syslog-snarf [options]

See L<"OPTIONS"> for details on the command line switches supported.
Output is to standard output, errors (under verbose mode) go to
standard error.

=head1 OPTIONS

This script currently supports the following command line switches:

=over 4

=item B<-h>, B<-?>

Prints a brief usage note about the script.

=item B<-l>

List available fields for templating the message format with the B<-f>
option.

=item B<-b> I<hostname>

Bind to specified hostname or address instead of everywhere. For testing
and to prevent remote connects, 127.1 would be used to bind only to the
localhost interface:

	-b 127.0.0.1

=item B<-p> I<port>

Listen on the specified UDP port instead of the default.

=back

=head1 EXAMPLES

=over 4

=item B<Forward logs from syslog-ng>

To have the syslog-ng daemon forward log messages to this script, add
the following to the syslog-ng.conf configuration file and restart
syslog-ng. The source statement will need to be altered to suit your
configuration file:

	destination testdaemon {
		udp("127.0.0.1" port (9999));
	};
	log { source(local); destination(testdaemon); };

=back

=head1 BUGS

=head2 Reporting Bugs

Newer versions of this script may be available from:

http://sial.org/code/perl/

If the bug is in the latest version, send a report to the author.
Patches that fix problems or add new features are welcome.

=head2 Known Issues

No known bugs.

=head1 SEE ALSO

perl(1), [RFC 3164]

=head1 AUTHOR

Jeremy Mates, http://sial.org/contact/

=head1 COPYRIGHT

The author disclaims all copyrights and releases this document into the
public domain.

=head1 HISTORY

Adapted from udp_echo_serv.pl by Lincoln D. Stein in the text
http://www.modperl.com/perl_networking/ (Chapter 18), plus data from
the Net::Syslog module as well as information in the sys/syslog.h
header file.

=head1 VERSION

$Id: syslog-snarf,v 2.1 2004/06/08 07:50:44 jmates Exp $

=cut
