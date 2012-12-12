#!/usr/bin/perl

use strict;
use warnings;

use Net::DNS;
use Net::DNS::RR;
use Time::HiRes qw(usleep);

use POE qw(Component::Server::DNS);

# POE::Kernel does filehandle activity detection - socket polling(?)

my $dns_server = POE::Component::Server::DNS->spawn( alias => 'dns_server',port=>5252 );

POE::Session->create(
      package_states => [ 'main' => [ qw(_start query_listener log) ], ],
);

$poe_kernel->run();
exit 0;

  sub _start {
    my ($kernel,$heap) = @_[KERNEL,HEAP];

    # Tell the component that we want log events to go to 'log'
    $kernel->post( 'dns_server', 'log_event', 'log' );

    # register a handler for any foobar.com suffixed domains
    $kernel->post( 'dns_server', 'add_handler', 
        { 
          event => 'query_listener', 
          # session => 'destination_session_event_is_in',
          label => 'foobar', 
          match => '.',
        } 
    );
    undef;
  }

  sub query_listener {
    my ($qname,$qclass,$qtype,$callback,$origin) = @_[ARG0..ARG4];
    my ($rcode, @ans, @auth, @add);
    print STDERR "Listener: From: $origin QN: $qname QC: $qclass QT: $qtype\n";

    if ($qtype eq "A") {
      my ($ttl, $rdata) = (3600, "10.1.2.3");
      push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
      $rcode = "NOERROR";
    } else { 
      $rcode = "NXDOMAIN";
    }

    $callback->($rcode, \@ans, \@auth, \@add, { aa => 1 });
    undef;
  }

  sub log {
    my ($ip_port,$net_dns_packet) = @_[ARG0..ARG1];
    $net_dns_packet->print();
    undef;
  }
