har: a High-Availability Resolver
=================================

Overview
--------
har is a "high availability resolver."  As you probably know, a DNS resolver's
duty is to convert host names (e.g., `api.example.com`) into IPv4 or IPv6
addresses (e.g., `1.2.3.4`).

Unlike [bind], [djbdns], [PowerDNS], or other DNS resolvers, har is _not_ a
full-service resolver authoritative for top-level or second-level domains (e.g.
`mycompany.com`).  har is not designed to accept connections from other hosts,
nor does har provide features such as caching or recursion.  Instead, har is
designed to resolve hostnames that you configure into IP addresses of hosts
that are _actually available_, based on criteria you specify.  Queries for
non-configured hostnames are simply forwarded to a full-service resolver.

[bind]: http://www.isc.org/software/bind
[djbdns]: http://cr.yp.to/djbdns.html
[PowerDNS]: http://www.powerdns.com/


Why use har?
------------
har is intended to be a building block for large-scale, highly-available
services.  For example, if your service architecture involves a front-end web
server that retrieves data from an API layer, har can help ensure that the
front-end code connects to the closest available API server.

har provides the following benefits over HTTP proxies:

* Most HTTP proxies don't maintain connection and response latency statistics.
  har helps direct clients to both an available _and_ proximate server.  This
  makes it easy to implement a design in which a client falls back to a server in
  another region (whose response latency necessarily will be longer) only if all
  of the servers in the same region are unavailable.

* Proxied connections usually disguise the connection's origin address (from
  the server's point of view) and the destination address (from the client's
  point of view).  This can present a challenge for debugging service issues.
  With har, you don't need to worry about that: clients can directly connect to
  the server's address.

* har helps isolate service issues: since every client runs its own copy, 
  the failure of a har instance only affects the client.  

* har improves speed: no extra network hop is needed that could introduce
  additional response latency.


Design
------
hard (the har daemon) is a DNS proxy server.  It answers DNS queries on the
IPv4 and IPv6 loopback interfaces by looking at the "question" section of the
request packet.  If the request is for an A or AAAA record (i.e., an IP
address), and the subject of the request (i.e., the hostname) is configured in
har's configuration file, har will consider itself the authoritative server and
respond to the request  Otherwise, har will simply forward the request to an
authoritative DNS server.

While har waits for queries, it periodically polls a list of one or more 
_candidates_ associated with each configured host.  A candidate is a specific
host whose IP address could be associated with the configured hostname.  For
example, candidates for the host `api.example.com` could be `api1.east.example.com`,
`api2.east.example.com`, `api1.west.example.com`, and so forth.  Candidates 
are polled and ranked either via HTTP or TCP health checks.  Check state is stored
in a local sqlite3 database.

    +-----------+
    |  program  |
    +-----------+
         ||
         || <- DNS query: "api.example.com" 
         ||    (localhost, port 53)
         \/
    +----------+
    |          |       ---------------          ----------
    |          | ---> (har config file)   |--> (sqlite3 db)
    |          |       ---------------    |     ----------
    |   hard   | --------------------------
    |          |
    |          | == HTTP health check ==> http://api1.west.example.com
    |          | == HTTP health check ==> http://api1.east.example.com
    |          | == HTTP health check ==> ...
    +----------+
         ||
         ||  <- outbound DNS queries ("api1.west.example.com")
         \/
    +-------------------------------------+
    | upstream resolver (ns1.example.com) | 
    +-------------------------------------+


Requirements
------------
har requires the following shared libraries to be installed on the client:

* [sqlite3](http://sqlite.org/)
* [libev](http://software.schmorp.de/pkg/libev.html)
* [libcurl](http://curl.haxx.se/libcurl/) (7.21.4 or later)
* [c-ares](http://c-ares.haxx.se/)
* [ldns](http://nlnetlabs.nl/projects/ldns/)
* [libconfuse](http://www.nongnu.org/confuse/)
* [uriparser](http://uriparser.sourceforge.net/)

At this time, har has been tested only on CentOS 5 Linux (x86_64 platform).  
Support for additional operating systems and distributions is forthcoming --
any assistance in this area would be most appreciated.

Building har
------------

    gcc -std=c99 -D_POSIX_SOURCE -Wall -pedantic -g har.c -o har -lev -lldns -lconfuse -lcurl -luriparser -lsqlite3

Configuration
-------------
TBD

Authors
-------
Michael S. Fischer <michael+har@dynamine.net> is the primary author and
maintainer.

Support
-------
Contact the author for support questions.  Since har is a volunteer project,
support is available only as the author's time permits.

Bug reports and feature requests can be filed at
<https://github.com/otterley/har/issues>.

Copyright and License
---------------------
Copyright 2011 Michael S. Fischer.

See the LICENSE file included with this distribution for the terms under which
har is licensed.

Source and contributions
------------------------
Contributions to har are welcome and encouraged.  The official GitHub
repository is located at <https://github.com/otterley/har>.
