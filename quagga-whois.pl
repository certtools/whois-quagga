#!/usr/bin/perl -w
#
#  Otmar Lendl <lendl@cert.at>
#
# /ol/2k9/07/16
#
#  Simple whois Interface to quagga
#

use strict;
use Sys::Syslog qw(:standard :macros);
use Socket;

my $read_timeout = 1;
my $quagga_timeout = 5;
my $table_timeout = 60;

my $testfile =  undef; #'/tmp/x';
my $testlines = 10000;

my $own_asn = 30971;
my $own_org = "CERT.at";
my $own_hostname = "qualle.cert.at";

$SIG{ALRM} = sub { print "Timeout\r\n"; exit(0) }; 
alarm $read_timeout;

my $input = <STDIN>;

alarm 0;

#print "Got $input";

$input =~ tr/-a-z0-9.: //cd;
#print "sanititzed: $input\n\n";

my ($port,$addr);
$addr = 'stdin';

eval {		# find my network peer
	($port,$addr) = sockaddr_in(getpeername(STDIN)); 
	$addr = inet_ntoa($addr);
};

openlog('bgp-whois', 'ndelay,nofatal,pid', LOG_LOCAL0);
setlogmask( LOG_UPTO(LOG_DEBUG) );
syslog(LOG_INFO, "Request from %s: %s", $addr, $input);
closelog();


my $p_block;
my $p_origin;
my $p_path;
my $p_mask;
my $p_community;
my $p_nexthop;
my $p_full;
my $debug;

if ($input =~ /help/i) {
	print <<EOM;

$own_org BGP whois.

Usage:

   \$ whois -h $own_hostname [tags] IP ...

   tags select specific BGP table attributes. Possible values:

	block	return the prefix in CIDR notation
	mask	return the netmask
	nexthop	return the next hop
	path	return the full AS-path
	origin	return the first AS in the path (ignore aggregation)
	community	return the community tags of the route
	nexthop	return the next hop of the route

    IP can be a list of IPv4 and IPv6 addresses.
    The special values "v4table" and "v6table" produce a dump of the full 
    routing tables. These dumps cannot include the community attribute.
    Unless nexthop is given, the tables will only contain the best route.

/ol/2k9/07/17, last change 2023/03/14

EOM
	exit 0;
}
	
$p_block = 1 if ($input =~ s/\bblock\b//);
$p_origin = 1 if ($input =~ s/\borigin\b//);
$p_path = 1 if ($input =~ s/\bpath\b//);
$p_mask = 1 if ($input =~ s/\bmask\b//);
$p_community = 1 if ($input =~ s/\bcommunity\b//);
$p_nexthop = 1 if ($input =~ s/\bnexthop\b//);
$debug = 1 if ($input =~ s/\bdebug\b//);

$input =~ s/^\s*(.*?)\s*/$1/;

@ARGV = split(/ +/, $input);

#print join(" X ", @ARGV), "\n";
$p_full = !($p_block or $p_origin or $p_path or $p_mask or $p_full or $p_community);

my ($best, $block, $origin, $path, $mask, $nexthop, $community, $dump, $flags, $ip1, $ip2, $nextline, $dummy);

my $command;
while(my $arg = shift(@ARGV)) {

	# defaults
	$block = $origin = $path = "NOTFOUND";
	$mask = 32; $community = "";
	$dump = 0;

	if ($arg =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d\d?)?$/) { # v4 address or block
		$command = "show ip bgp $arg";
	} elsif ( $arg eq "v4table") {		# full v4 table?
		$command = "show ip bgp";
		$dump = 1;
	} elsif ( $arg =~ /^[[:xdigit:]:]+(\/\d\d?)?$/) {		# v6 address or block
		$command = "show ipv6 bgp $arg";
	} elsif ( $arg eq "v6table") {		# full v6 table?
		$command = "show ipv6 bgp";
		$dump = 1;
	} else {
		print "Unknown query for >>$arg<<\n";
		next;
	}

#	print "command = $command\n";

	alarm(($dump) ? $table_timeout : $quagga_timeout);

	if ($testfile) {
		open(QUA, "head -300 $testfile |") or die "can't contact quagga";
	} else {
		open(QUA, "vtysh -c '$command' |") or die "can't contact quagga";
	}

#BGP routing table entry for 2001:238:700::/41
#Paths: (1 available, best #1, table Default-IP-Routing-Table)
#  Not advertised to any peer
#  30971 1764 8218 9505
#    ::ffff:83.136.32.10 from 83.136.32.10 (83.136.32.10)
#      Origin IGP, localpref 100, valid, external, best
#      Community: 1764:20043 1764:30001 1764:40030 8218:102
#      Last update: Thu Jul 16 15:24:01 2009
#
#BGP routing table entry for 141.201.0.0/16
#Paths: (1 available, best #1, table Default-IP-Routing-Table)
#  Not advertised to any peer
#  30971 1109
#    83.136.32.10 from 83.136.32.10 (83.136.32.10)
#      Origin IGP, localpref 100, valid, external, best
#      Last update: Thu Jul 16 15:24:06 2009

# WARNING: special case own netblock:
#BGP routing table entry for 83.136.32.0/21
#Paths: (1 available, best #1, table Default-IP-Routing-Table)
#  Advertised to non peer-group peers:
#  144.76.209.108
#  Local
#    83.136.32.5 from 83.136.34.65 (83.136.34.65)
#      Origin IGP, metric 254, localpref 100, valid, internal, best
#      Last update: Tue Sep 30 09:51:30 2014

# When doing dumps, it's this:
# Status codes: s suppressed, d damped, h history, * valid, > best, i - internal,
#              r RIB-failure, S Stale, R Removed
#
#
#   Network          Next Hop            Metric LocPrf Weight Path
#*>i1.12.0.0/24      81.16.144.11             0    110      0 1764 174 4134 4847 18245 i
#*>i1.24.0.0/13      81.16.144.11             0    110      0 1764 174 4837 i
#*>i3.0.0.0          81.16.144.11             0    110      0 1764 3356 6453 9304 80 i
#*                   193.171.13.65            0             0 1853 1764 8359 i
#*>i83.136.32.0/21   83.136.34.68           254    100      0 i
#*>i83.136.33.0/24   83.136.34.68           254    100      0 i

#
# or
#   Network          Next Hop            Metric LocPrf Weight Path
#*>i2001:3c8::/32    2001:628::1              0    100      0 1853 20965 24490 24475 4621 i
#*>i10c0:1100::/24   2a01:190:1764:144::11
#                                            0    100      0 1764 174 376 376 376 851 i
#*>i2001:418:3803::/48
#                    2001:858:66:2::1:11
#                                             0    100      0 3248 2914 12008 i
#*> ::/0 ::ffff:86.59.44.31 0 3248 8437 i


#
# ARGH. metric / locpref is not always present. and fscking fixed format output.
# We assume weight = 0 for now. /ol/2011/10/28
#
# and I see:
#   Network          Next Hop            Metric LocPrf Weight Path
#*  77.116.0.0/14    81.16.144.11                           0 1764 25255 i
#*>i                 193.203.0.96             1    150      0 25255 i

# /ol/17/03/07: new idea, insert a seperator a the fixed col
# 's/^(\*.{58}\d )/$1 XX /' 

# /ol/23/03/14: new idea, reformat with longer fields for block and nexthop befor parsing

	if ($dump) {		# skip inital block
		while (<QUA>) {
			last if /^$/;
		}
		$_ = <QUA>;	# col headers
	}


	while (<QUA>) {
		if ($dump) {
#			print STDERR "Got $_" if ($debug);
			chomp;
			next unless (/^\*/);	# all routing table entries start with *

			my $line = $_;		# Build one string even if line was split

# linebreak because block was too long?
			if (substr($line,19,1) eq " ") {        # there is a space between block an nexthop
#				print STDERR "[", substr($line,19,1),"] No contiuation after Block for $line\n" if ($debug);
				substr($line,19,1,(" " x 21));  # insert 20 spaces
			} else {
#				print STDERR "[", substr($line,19,1),"] Contiuation after Block for $line\n" if ($debug);
				$_ = <QUA>;
				chomp;
				die "contiuation line doesn't start with [ ]" unless (/^ /);
				s/^ +//;        # remove leading whitespace
				$line .= (" " x (40 - length($line))) . $_;	
			}

# linebreak because nexthop was too long?
			if (substr($line,58,1) eq " ") {        # there is a space after nexthop
#				print STDERR "[", substr($line,58,1),"] No contiuation after nexthop for $line\n" if ($debug);
				substr($line,58,1,(" " x 21));  # insert 20 spaces
			} else {
#				print STDERR "[", substr($line,58,1),"] Contiuation after nexthop for $line\n" if ($debug);
				$_ = <QUA>;
				chomp;
				die "contiuation line doesn't start with [ ]" unless (/^ /);
				s/^[ ]{40}//;   # remove 40 leading whitespace
				$line .= (" " x (80 - length($line))) . $_;
			}


			print STDERR "Joined: $line\n" if ($debug);
#			if ($line =~ /^\*[ >][ei ]([\d:.\/]+)/) { # start of a route entry, new block value
#				$block = $1;
#			}
			if ($line =~ /^\*[ >][ei ]/) { # a routing table entry

#   Network                              Next Hop                                Metric LocPrf Weight Path
#         1         2         3         4         5         6         7         8         9         0               
#123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890
#*>i                                     193.203.0.185                                0    150      0 6939 4651 23969 i
#*  1.0.129.0/24                         193.171.13.65                                0             0 1853 9002 38040 23969 i
#*> ::/0                                 ::ffff:62.218.0.248                                        0 8437 25255 i

				my ($star, $status, $origin_code, $bl, $nh, $metric, $locprf, $weight, $path) = 
					unpack("a1a1a1A36xA39xA6xA6xA6xA*", $line);
#						1 1 1 36 1 40

				print STDERR "GOT: $star, $status, $origin_code, $bl, $nh, $metric, $locprf, $weight, $path\n" if ($debug);
				$nexthop = $nh;
				$best = (defined($status) and ($status eq ">")) ? 1 : 0;

# parse out $block (prefix)
				if ($bl eq "") {		# no block given as this is another route for same prefix
					1;
				} elsif (($ip1,$ip2,$mask) = ($bl =~ /^(\d+)\.(\d+\.\d+\.\d+)(\/\d+)?$/)){ # ipv4 route
					# canonify prefix
					if (defined($mask)) {
						1;
					} elsif ($ip1 < 128) {
						$mask = '/8';
					} elsif ($ip1 < 192) {
						$mask = '/16';
					} elsif ($ip1 < 224) {
						$mask = '/24';
					} else {
						die "$_ is not a unicast network\n";
					}
					$block = $ip1 . '.' . $ip2  . $mask;
					next if ($block eq '0.0.0.0/0');    # ignore default route
					$mask =~ s,^/,,;
				} elsif (($ip1,$mask) = ($bl =~ /^([[:xdigit:]]*:[[:xdigit:]:]+)(\/\d+)$/)) {	#ipv6 route
					$block = $ip1 . $mask;
					next if ($block eq '::/0');    # ignore default route
					$mask =~ s,^/,,;
					$best = (defined($best) and ($best eq ">")) ? 1 : 0;
				} else {
					print STDERR "Could not parse >>$_<<\n";
					next;
				}

			$path =~ s/ [ei\?]$//;	# remove origin code (i e ?)

			$origin = $path;
			$origin =~ s/ *\{.*?\}//;	# remove aggregation info
			$origin =~ s/,.*//;
			$origin =~ s/.* (\d+)/$1/;

			$path = $origin = $own_asn if ($path eq "");	# empty path -> iBGP path, give our own ASN

			next if (!$p_nexthop and !$best);	# only show best route unless asked for nexthop
			print "$_\n" if ($p_full);	
			print "$arg" unless ($p_full);
			print " $block" if ($p_block);
			print " $mask" if ($p_mask);
			print " $nexthop" if ($p_nexthop);
			print " $path" if ($p_path);
			print " $origin" if ($p_origin);
			print "\r\n" unless ($p_full);
			}
		} else {	# single routing table entry
			if (/BGP routing table entry for (\S+)\/(\d+)/) {
				$block = "$1/$2";
				$mask = $2;
			} elsif (/^  (\d+\.\d+\.\d+\.\d+)/) {
				1;		# IP address, must be peers info
			} elsif (/^  (\d+ ?[\d{}, ]*)/) {
				$path = $1;
				$origin = $path;
				$origin =~ s/ *\{.*?\}//;
				$origin =~ s/,.*//;
				$origin =~ s/.* (\d+)/$1/;
			} elsif (/^  Local/) {
				$path = $origin = $own_asn;
			} elsif (/Community: ([\d\w :-]+)/) {
				$community = $1;
			}
			print if ($p_full);
		}

	}

	unless ($dump) {
		print "$arg" unless ($p_full);
		print " $block" if ($p_block);
		print " $mask" if ($p_mask);
		print " $path" if ($p_path);
		print " $origin" if ($p_origin);
		print " $community" if ($p_community);
		print "\r\n" unless ($p_full);
	}
}

