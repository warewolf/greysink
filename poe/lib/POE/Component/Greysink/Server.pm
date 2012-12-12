package POE::Component::Greysink::Server;
use POE;
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
	object_states => [
	  $self => [ qw(_start _stop complete step_a step_b step_c) ],
	],
  );
  return $self;
}

# query request handler
sub query {
  # posts to each resolver object with a postback of resolver return state - fallthrough or hit - postback in ::Server session stores status in _HEAP per socket/port pair
  # when hit, 
}

sub resolver_response {
  # event listening for resolver postbacks - one event per resolver
  # stores status in _HEAP per socket/port pair and resolver friendly name
  # ARGS: resolver, hit?, record_ref
  # ... this needs to know how many/what names there are of resolvers.
}

sub _stop {#{{{
  print "Session ", $_[SESSION]->ID, " has stopped.\n";
}#}}}

sub _start {#{{{
  my ($self, $kernel, $heap, $session) = @_[OBJECT, KERNEL, HEAP, SESSION];
  print "Session ", $session->ID, " has started.\n";
  $kernel->alias_set("greysink");
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
