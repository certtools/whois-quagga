#!/usr/bin/perl -w
#
#  Otmar Lendl <lendl@cert.at>
#
# /ol/2k9/07/16
#
#  Simple whois Interface to quagga
# 
# 
#

use strict;


my $read_timeout = 1;
my $quagga_timeout = 5;
my $table_timeout = 60;

my $own_asn = 30971;

$SIG{ALRM} = sub { print "Timeout\r\n"; exit(0) };
alarm $read_timeout;

my $input = <STDIN>;

alarm 0;

#print "Got $input";

$input =~ tr/-a-z0-9.: //cd;
#print "sanititzed: $input\n\n";


my $p_block;
my $p_origin;
my $p_path;
my $p_mask;
my $p_community;
my $p_full;
my $debug;
my $ORG = "CERT.at";


if ($input =~ /help/i) {
    print <<EOM;

$ORG BGP whois.

Usage:

   \$ whois -h <hostname> [tags] IP ...

   tags select specific BGP table attributes. Possible values:

    block   return the prefix in CIDR notation
    mask    return the netmask
    path    return the full AS-path
    origin  return the first AS in the path (ignore aggregation)
    community   return the community tags of the route

    IP can be a list of IPv4 and IPv6 addresses.
    The special values "v4table" and "v6table" produce a dump of the full
    routing tables. These dumps cannot include the community attribute.

/ol/2k9/07/17, last change 2010/05/24

EOM
    exit 0;
}

$p_block = 1 if ($input =~ s/\bblock\b//);
$p_origin = 1 if ($input =~ s/\borigin\b//);
$p_path = 1 if ($input =~ s/\bpath\b//);
$p_mask = 1 if ($input =~ s/\bmask\b//);
$p_community = 1 if ($input =~ s/\bcommunity\b//);
$debug = 1 if ($input =~ s/\bdebug\b//);

$input =~ s/^\s*(.*?)\s*/$1/;

@ARGV = split(/ +/, $input);

#print join(" X ", @ARGV), "\n";
$p_full = !($p_block or $p_origin or $p_path or $p_mask or $p_full or $p_community);

my ($block, $origin, $path, $mask, $community, $dump, $flags, $ip1, $ip2, $nextline, $dummy);

my $command;
while(my $arg = shift(@ARGV)) {

    # defaults
    $block = $origin = $path = "NOTFOUND";
    $mask = 32; $community = "";
    $dump = 0;

    if ($arg =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d\d?)?$/) { # v4 address or block
        $command = "show ip bgp $arg";
    } elsif ( $arg eq "v4table") {      # full v4 table?
        $command = "show ip bgp";
        $dump = 1;
    } elsif ( $arg =~ /^[[:xdigit:]:]+(\/\d\d?)?$/) {       # v6 address or block
        $command = "show ipv6 bgp $arg";
    } elsif ( $arg eq "v6table") {      # full v6 table?
        $command = "show ipv6 bgp";
        $dump = 1;
    } else {
        print "Unknown query for >>$arg<<\n";
        next;
    }

#   print "command = $command\n";

    alarm(($dump) ? $table_timeout : $quagga_timeout);
    open(QUA, "vtysh -c '$command' |") or die "can't contact quagga";

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
#
# or
#   Network          Next Hop            Metric LocPrf Weight Path
#*>i2001:3c8::/32    2001:628::1              0    100      0 1853 20965 24490 24475 4621 i
#*>i10c0:1100::/24   2a01:190:1764:144::11
#                                            0    100      0 1764 174 376 376 376 851 i
#*>i2001:418:3803::/48
#                    2001:858:66:2::1:11
#                                             0    100      0 3248 2914 12008 i

#
# ARGH. metric / locpref is not always present. and fscking fixed format output.
# We assume weight = 0 for now. /ol/2011/10/28
#
# and I see:
#   Network          Next Hop            Metric LocPrf Weight Path
#*  77.116.0.0/14    81.16.144.11                           0 1764 25255 i
#*>i                 193.203.0.96             1    150      0 25255 i



    while (<QUA>) {
        if ($dump) {
#           print STDERR "Got $_";
            chomp;
            if (/^\*[ >][ei ][\d:.\/]+/) { # start of a route entry
                if (/\/\d+$/) {
                    $nextline = <QUA>;
                    chomp($nextline);
                    $_ = $_ . $nextline;
#                   print STDERR "merged: $_\n";
                }
                    if (/[.:]\d+$/) {
                    $nextline = <QUA>;
                    chomp($nextline);
                    $_ = $_ . $nextline;
#                   print STDERR "merged: $_\n";
                }
# re-insert network for multipath routes
                if (/^\*[ >][ei ]  /) {
                    s/^(\*[ >][ei ]) + /$block /;
                    print STDERR "Replaced: $_\n";
                }
                s/\s+/ /g;  # canonize whitespace
# v4
                    if (($ip1,$ip2,$mask,$dummy,$path,$flags) = /^\*>?[ei ](\d+)\.(\d+\.\d+\.\d+)(\/\d+)?(.*?\s0\s)([\d{,} ]+) ([ei\?])$/) {
                    next if ($ip1 == 0);    # ignore default route
# print STDERR "$_\n ($ip1,$ip2,$mask,$path,$flags)\n";
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
                    $mask =~ s,^/,,;
# v6
                } elsif (($ip1,$mask,$dummy,$path,$flags) = /^\*>?[ie ]([[:xdigit:]]+:[[:xdigit:]:]+)(\/\d+)(.*?\s0\s)([\d{,} ]+) ([ei\?])$/) {
                    $block = $ip1 . $mask;
                    $mask =~ s,^/,,;
                } else {
                    print STDERR "Could not parse >>$_<<\n";
                    next;
                }
            $origin = $path;
            $origin =~ s/ *\{.*?\}//;
            $origin =~ s/,.*//;
            $origin =~ s/.* (\d+)/$1/;

            print "$_\n" if ($p_full);
            print "$arg" unless ($p_full);
            print " $block" if ($p_block);
            print " $mask" if ($p_mask);
            print " $path" if ($p_path);
            print " $origin" if ($p_origin);
            print "\r\n" unless ($p_full);
            }
        } else {    # single routing table entry
            if (/BGP routing table entry for (\S+)\/(\d+)/) {
                $block = "$1/$2";
                $mask = $2;
            } elsif (/^  (\d+\.\d+\.\d+\.\d+)/) {
                1;      # IP address, must be peers info
            } elsif (/^  (\d+ ?[\d{}, ]*)/) {
                $path = $1;
                $origin = $path;
                $origin =~ s/ *\{.*?\}//;
                $origin =~ s/,.*//;
                $origin =~ s/.* (\d+)/$1/;
            } elsif (/^  Local/) {
                $path = $origin = $own_asn;
            } elsif (/Community: ([\d\w :]+)/) {
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
