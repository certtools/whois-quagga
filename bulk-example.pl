#!/usr/bin/perl -w
#
# Otmar Lendl <lendl@cert.at> 2009/09/02
#
#

use strict;
use Getopt::Long;
use DBI;
use Net::CIDR ':all';
use Data::Dumper;
use Net::Patricia;

my $cidrtree = new Net::Patricia;
my $debug = 0;
my $sep=';';

&GetOptions (   "d",  \$debug, 
		"s=s", \$sep,
		);


open(O, "whois -h qualle.cert.at v4table block origin |") or die "opening Qualle";

print STDERR "Loading Routing table : " if ($debug);
my $count = 0;
while($_ = <O>) {
	if (/^v4table ([0-9.\/]+)\s(\d+)/) {
		$cidrtree->add_string($1, $2);
		if ($debug) {
			print STDERR "." unless ($count++ % 1000) 
		}
	}
}
close(O);


print STDERR "\nLoaded $count prefixes\n" if ($debug);

$count = 0;
while(<>) {
	s/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/ip2origin($1)/ge;
	print;
#	print STDERR "." unless ($count++ % 1000);
}

sub ip2origin {
	my $ip = $_[0];
	my $str = "";
	my $id;

	#
	# where is it in the radix tree?
	#
	eval {
	my $origin = $cidrtree->match_string($ip);
	if (defined($origin)) {
		return($ip . $sep . $origin);
 	} else {
		return("$ip (NO match)");
	}
	}
}

