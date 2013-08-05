#!/usr/bin/perl
# vim: foldmethod=marker
use strict;
use warnings;
use lib qw(lib);
sub POE::Kernel::ASSERT_DEFAULT () { 1 } # XXX FIXME disable in production
use POE qw(Component::Greysink::Handler);
use POEx::Inotify;
use Linux::Inotify2;
use POSIX qw(setsid);
# XXX FIXME consider using POE::Component::Daemon for Apache style pre-forking for more processes
# This will require hacking up POE::Component::Server::DNS to accept sockets (or a wheel) passed in
use Proc::Daemon;

# daemonizing code - XXX 
# This has to come first, otherwise POE complains.  It prefers fork first, then session startup.
# This has a downsize of making run-time errors not show up on the console, but in the log. :(
print "Errors (if any) will be written to the logfiles.\n";

# Nameservers talk to for recursive lookups
#my $upstream_nameservers = ( "8.8.8.8","8.8.4.4" ); # (google public DNS example)
my $upstream_nameservers = [ "8.8.8.8","8.8.4.4" ];

my $daemon = Proc::Daemon->new(
  work_dir => '.', # Where the PID, log files, and blacklist/whitelist files belong
  pid_file => 'greysink.pid',
  child_STDOUT => '+>>greysink.log',
  child_STDERR => '+>>greysink.log',
);

# RNDC key to talk to BIND to flush zones from the cache when our blacklist/whitelists change
my $rndc_key = "QmFzZTY0SXNOZWF0byA6KQ==";

# fork off the child daemon, and let the parent exit.
my $Kid_1_PID = $daemon->Init;

unless ( $Kid_1_PID ) { # {{{
  # child process (daemon) here

  POSIX::setsid();

  # inotify handler used globally - monitor requests get sent back to sessions that requested them
  # which means the sink sessions have to request them.
  POEx::Inotify->spawn( alias=>'inotify' );

  # resolver used globally
  my $resolver = POE::Component::Client::DNS->spawn(
    Alias => "resolver",
    Nameservers => $upstream_nameservers,
  );

  # whitelist sinkhole session - uses above resolver
  my $whitelist_sink_session = POE::Component::Greysink::Whitelist->spawn( # {{{
    resolver => $resolver, # give the sink access to the resolver object
    alias => "whitelist", # what our alias is for the Greysink server to know us by
    list => "whitelist-list.txt", # where to get our list of zones that are spoofed
    inotify => "inotify", # tell sink where our inotify session is
    rndc_key => $rndc_key,
  ); # }}}

  # malware sinkhole session - uses above resolver # {{{
  my $malware_sink_session = POE::Component::Greysink::Sink->spawn(
    resolver => $resolver, # give the sink access to the resolver object
    alias => "malware", # what our alias is for the Greysink server to know us by
    list => "malware-list.txt", # where to get our list of zones that are spoofed
    inotify => "inotify", # tell sink where our inotify session is
    rndc_key => $rndc_key, # for flushing changes from caching bind infront of us
    authority => { # these are the authority records that will be served in responses
      A => '* 86400 IN A 192.168.100.1', # XXX change this to the IP of this nameserver
      NS => '* 86400 IN NS malware.cirt.example.com',
      SOA => '* 86400 IN SOA malware.cirt.example.com. cirt.example.com.  ( 42 28800 14400 3600000 86400)',
    },
    records => { # these are the records that will be filled in as answers to lookups
      A  => '* 86400 IN A 172.16.0.1', # XXX change this to the IP of some kind of device that listens/captures traffic
      NS => '* 86400 IN NS ns.sinkhole.example.com',
      SOA => '* 86400 IN SOA malware.cirt.example.com. cirt.example.com.  ( 42 28800 14400 3600000 86400)',
    },
  ); # }}}

  # ads sinkhole session - uses above resolver # {{{
  my $ads_sink_session = POE::Component::Greysink::Sink->spawn(
    resolver => $resolver, # give the sink access to the resolver object
    alias => "ads", # what our alias is for the Greysink server to know us by
    list => "ads-list.txt", # where to get our list of zones that are spoofed
    inotify => "inotify", # tell sink where our inotify session is
    rndc_key => $rndc_key, # for flushing changes from caching bind infront of us
    authority => { # these are the authority records that will be served in responses
      A => '* 86400 IN A 192.168.100.1', # XXX change this to the IP of this nameserver
      NS => '* 86400 IN NS ads.cirt.example.com',
      SOA => '* 86400 IN SOA ads.cirt.example.com. cirt.example.com.  ( 42 28800 14400 3600000 86400)',
    },
    records => { # these are the records that will be filled in as answers to lookups
      A  => '* 86400 IN A 172.16.0.0', # XXX change this to the IP of some kind of device that listens/captures traffic
      NS => '* 86400 IN NS ns.sinkhole.example.com',
      SOA => '* 86400 IN SOA ads.cirt.example.com. cirt.example.com.  ( 42 28800 14400 3600000 86400)',
    },
  ); # }}}

  # The greysink DNS server
  my $server = POE::Component::Greysink::Handler->spawn( # {{{
      recursive => 1, # do we fall through to recursive resolution?
      learn => 1, # do we automatically add zones from listed nameservers based on recursion? XXX FIXME this doesn't do anything
      sink_aliases => [ qw(whitelist malware ads) ], # order matters here, earlier in the list = higher precedence
      resolver => $resolver, # tell the Greysink server where the resolver is for recursion
      port => 5252, # tcp/udp port to bind to - tell BIND to forward to this
      address => "0.0.0.0", # ip to bind to - tell BIND to forward to this
      alias => 'greysink_handler', # Greysink::Handler POE session alias
      server_alias => 'greysink_server', # Component::Server::DNS POE session alias
  ); # }}}

  # start it up.
  POE::Kernel->run();
} # }}}

# parent process exits
exit 0;
