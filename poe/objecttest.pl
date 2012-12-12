#!/usr/bin/perl

use strict;
use warnings;
use lib qw(lib);
use POE qw(Component::Greysink::Server Component::Greysink::Sink Component::Client::DNS);
use Data::Dumper;

# resolver used globally
my $named = POE::Component::Client::DNS->spawn(
  Alias => "named"
);

# whitelist sinkhole session - uses above resolver
my $whitelist_sink_session = POE::Component::Greysink::Sink->spawn(
  resolver => "named", # tell the sink the resolver session alias
  alias => "whitelist", # what our alias is for the Greysink server to know us by
  list => "whitelist.txt", # where to get our list of zones that are spoofed
  source => "external", # authorative NS and spoofed records are external (but will be redacted)
);

# blacklist sinkhole session - uses above resolver
my $blacklist_sink_session = POE::Component::Greysink::Sink->spawn(
  resolver => "named", # tell the sink the resolver session alias
  alias => "blacklist", # what our alias is for the Greysink server to know us by
  list => "blacklist.txt", # where to get our list of zones that are spoofed
  source => "internal", # authorative NS and spoofed records are internal
  authority => {
    A => '* 86400 IN A 192.168.100.100',
    NS => '* 86400 IN NS ns.sinkhole.example.com',
    SOA => '* 86400 IN SOA ns.sinkhole.example.com. cert.example.com.  ( 42 28800 14400 3600000 86400)',
  },
  records => {
    A  => '* 86400 IN A 10.1.2.3',
    NS => '* 86400 IN NS ns.sinkhole.example.com',
    SOA => '* 86400 IN SOA ns.sinkhole.example.com. cert.example.com.  ( 42 28800 14400 3600000 86400)',
  },
);

my $server = POE::Component::Greysink::Server->spawn(
    recursive => 1, # do we fall through to recursive resolution?
    learn => 1, # do we learn new whitelist/blacklist based on recursion?
    sink_aliases => [ qw(whitelist blacklist) ],
    resolver => "named", # tell the server where the resolver is for recursion
);

POE::Kernel->run();
