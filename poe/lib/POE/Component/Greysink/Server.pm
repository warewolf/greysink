package POE::Component::Greysink::Server;
use POE qw(Component::Server::DNS);
use strict;
use warnings;
use Data::Dumper;


# Spawn a new PoCo::Greysink session.  This basically is a
# constructor, but it isn't named "new" because it doesn't create a
# usable object.  Instead, it spawns the object off as a session.

# this will set up the DNS listener session, sending events back to the Greysink::Server session.
sub spawn {
  my $class = shift;
  my %args = @_;
  my $self = bless { }, $class;
  print Data::Dumper->Dump([\%args],[qw($args)]);

  $self->{session_id} = POE::Session->create(
	args => [
          map { defined($args{$_}) ? ($_,$args{$_}) : () } qw(recursive learn sink_aliases resolver port address),
        ],
	object_states => [
	  $self => [ qw(_start _stop
                        query_handler resolver_response

                        complete step_a step_b step_c
                   ) ],
	],
  );
  return $self;
}

# query request handler - this is hit by POE::Component::Client::DNS
sub query_handler {
  my ($self, $kernel, $heap, $session, $qname,$qclass,$qtype,$callback,$origin) = @_[OBJECT, KERNEL, HEAP, SESSION,ARG0..ARG4];
  my ($rcode, @ans, @auth, @add);
  printf STDERR "Server query_handler: QO: %s QC: %s QT: %s QN: %s\n",$origin,$qclass,$qtype,$qname;

  # send queries to sinkholes
  foreach my $sink (@{$heap->{greysink}->{sinks}}) {
    # give the sinkhole a method to record its response, and tie it to the origin
    my $postback = $session->postback("resolver_response",$origin);
    # ask the sink to do a lookup, w/ the query + postback to respond through
    $kernel->post($sink,"lookup",$postback,$qname,$qclass,$qtype);
  }

  ### XXX FIXME TEMPORARY CODE BE HERE

  if ($qtype eq "A") {
    my ($ttl, $rdata) = (3600, "10.1.2.3");
    push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
    $rcode = "NOERROR";
  } else {
    $rcode = "NXDOMAIN";
  }

  $callback->($rcode, \@ans, \@auth, \@add, { aa => 1 });
  ### XXX FIXME TEMPORARY CODE BE HERE
}

sub resolver_response {
  my ($self, $kernel, $heap, $session, $passthru,$passback) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0, ARG1];
  print Data::Dumper->Dump([$passthru,$passback],[qw($passthru $passback)]);
  # event listening for resolver postbacks - one event per resolver
  # stores status in _HEAP per socket/port pair and resolver friendly name
  # ARGS: resolver, hit?, record_ref
  # ... this needs to know how many/what names there are of resolvers.
}

sub _stop {#{{{
  print "Session ", $_[SESSION]->ID, " has stopped.\n";
}#}}}

sub _start {#{{{
  my ($self, $kernel, $heap, $session, %args) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0.. $#_];
  print "Session ", $session->ID, " has started.\n";
  $kernel->alias_set("greysink");

  # save off our "child" sink aliases
  $heap->{greysink}->{sinks} = $args{sink_aliases};

  my $dns_server = POE::Component::Server::DNS->spawn(
    map { defined($args{$_}) ? ($_ , $args{$_}) : () } qw(port address resolver_opts),
    alias => 'dns_server',
  );

  # set up DNS listener
  $kernel->post( 'dns_server', 'add_handler', {
      session => 'greysink',
      event => 'query_handler',
      label => 'ZA_WARUDO',
      match => '.',
  });

  my $postback = $session->postback("complete","dns_connection_socketpair_maybe");
  my ($qname,$qclass,$qtype) = qw(foobar.com IN A);
  $kernel->yield('step_a',$qname,$qclass,$qtype,$postback);
}#}}}

sub complete {#{{{
  my ($self, $kernel,$heap,$session,$passthru,$passback) = @_[OBJECT, KERNEL,HEAP, SESSION,ARG0,ARG1];
  print Data::Dumper->Dump([$passthru,$passback],[qw($passthru $passback)]);
}#}}}

sub step_a {#{{{
  my ($self,$kernel,$heap,$session,$qname,$qclass,$qtype,$postback) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0..ARG3];
  if (rand()*10%2==0) {
    print "STEP A: Hit, we stop here.\n";
    $postback->($qname,$qclass,$qtype,"postback_arg3");
  } else {
    print "STEP A: Miss, we move down the chain\n";
    $kernel->yield('step_b',$qname,$qclass,$qtype,$postback);
  }
}#}}}

sub step_b {#{{{
  my ($self,$kernel,$heap,$session,$qname,$qclass,$qtype,$postback) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0..ARG3];
  if (rand()*10%2==0) {
    print "STEP B: Hit, we stop here.\n";
    $postback->($qname,$qclass,$qtype,"postback_arg3");
  } else {
    print "STEP B: Miss, we move down the chain\n";
    $kernel->yield('step_c',$qname,$qclass,$qtype,$postback);
  }
}#}}}

sub step_c {#{{{
  my ($self,$kernel,$heap,$session,$qname,$qclass,$qtype,$postback) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0..ARG3];
  print "STEP C: we stop here.\n";
  $postback->($qname,$qclass,$qtype,"postback_arg3");
}#}}}



1;
