#!/usr/bin/perl

use strict;
use warnings;
use lib qw(lib);
#sub POE::Kernel::ASSERT_DEFAULT () { 1 }
use POE qw(Component::Greysink::Handler);
#use Data::Dumper;
use POEx::Inotify;
use Linux::Inotify2;
use Carp::Always;

# inotify handler used globally - monitor requests get sent back to sessions that requested them
# which means the sink sessions have to request them.
POEx::Inotify->spawn( alias=>'inotify' );

# resolver used globally
my $named = POE::Component::Client::DNS->spawn(
  Alias => "named"
  # resolvers => [ 1.2.3.4, 4.5.6.7 ];
);

# whitelist sinkhole session - uses above resolver
my $whitelist_sink_session = POE::Component::Greysink::Whitelist->spawn(
  resolver => $named, # give the sink access to the resolver object
  alias => "whitelist", # what our alias is for the Greysink server to know us by
  list => "whitelist.txt", # where to get our list of zones that are spoofed
  inotify => "inotify", # tell sink where our inotify session is
);

# blacklist sinkhole session - uses above resolver
my $blacklist_sink_session = POE::Component::Greysink::Sink->spawn(
  resolver => $named, # give the sink access to the resolver object
  alias => "blacklist", # what our alias is for the Greysink server to know us by
  list => "blacklist.txt", # where to get our list of zones that are spoofed
  inotify => "inotify", # tell sink where our inotify session is
  authority => { # these are the authority records that will be served in responses
    A => '* 86400 IN A 192.168.100.100',
    NS => '* 86400 IN NS ns.sinkhole.example.com',
    SOA => '* 86400 IN SOA ns.sinkhole.example.com. cert.example.com.  ( 42 28800 14400 3600000 86400)',
  },
  records => { # these are the records that will be filled in as answers to lookups
    A  => '* 86400 IN A 10.1.2.3',
    NS => '* 86400 IN NS ns.sinkhole.example.com',
    SOA => '* 86400 IN SOA ns.sinkhole.example.com. cert.example.com.  ( 42 28800 14400 3600000 86400)',
  },
);

my $server = POE::Component::Greysink::Handler->spawn(
    recursive => 1, # do we fall through to recursive resolution?
    learn => 1, # do we automatically add zones from listed nameservers based on recursion?
    sink_aliases => [ qw(whitelist blacklist) ],
    resolver => $named, # tell the server where the resolver is for recursion
    port => 5252, # tcp/udp port to bind to
    address => "0.0.0.0", # ip to bind to
    alias => 'greysink_handler', # Greysink::Handler alias
    server_alias => 'greysink_server', # Component::Server::DNS alias
);

POE::Kernel->run();
