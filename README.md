# quagga whois

Whois interface to quagga (BGP routing daemon) to do IP to ASN lookups

This code was developed by Otmar Lendl <lendl@cert.at> and released under the GNU AFFERO GENERAL PUBLIC LICENSE.

See the corresponding LICENSE file.


# What does it do?

This script gets added to ``/etc/inetd.conf`` for port 43 [whois, RFC3912](https://tools.ietf.org/html/rfc3912) requests.
It will then look at the request. If it's an IP address, it will look up the current ASN which announces the most specific
matching netblock enclosing the ip address and return this ASN.



# Usage

```

$ whois -h localhost help

CERT.at BGP whois.

Usage:

   $ whois -h qualle.cert.at [tags] IP ...

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


```

Example: let's assume you want to figure out the ASN of the IP address 83.136.33.1:

```
$ whois -h localhost origin 83.136.33.1
83.136.33.1 30971
```

Hence the ASN is 30971.




# Requirements

A working quagga instance with a full BGP table feed. A working ``vtysh -c`` command.


# How to install?


Put this into /etc/inetd.conf:

```
whois   stream  tcp     nowait  nobody  /usr/local/bin/quagga-whois.pl quagga-whois.pl
```

Adjust the paths to your needs of course.

Next, edit the quagga-whois.pl script and replace ``my $ORG = "CERT.at";`` (CERT.at) with your organisation name.



# Contributing

Pull requests are on github welcome, but have a high chance of being missed.
A mail to the author is recommended.



