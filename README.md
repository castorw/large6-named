# large6-named
DNS nameserver designed specifically to cover large IPv6 segments

## Overview
### The Problem
Problem faced with IPv6 networks is network segments with network mask of /64, which is intended for regular use as minimum prefix length. Covering segments like these with classical DNS (eg. BIND) is not easily possible as these systems are record based and creating a zone file for a /64 network prefix is not possible.

### The Solution
This domain name server implementation is not a standard record base domain name server. This system rather responds to queries dynamically. It's configuration is made specifically to cover network prefixes and creates the records dynamically.
