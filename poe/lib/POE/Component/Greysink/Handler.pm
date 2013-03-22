package POE::Component::Greysink::Handler;
use POE qw(Component::Server::DNS);
use strict;
use warnings;
use Data::Dumper;


# Spawn a new PoCo::Greysink session.  This basically is a
# constructor, but it isn't named "new" because it doesn't create a
# usable object.  Instead, it spawns the object off as a session.

# this will set up the DNS listener session, sending events back to the Greysink::Handler session.
sub spawn {
  my $class = shift;
  my %args = @_;
  my $self = bless { }, $class;

  $self->{session_id} = POE::Session->create(
	args => [
          map { defined($args{$_}) ? ($_,$args{$_}) : () } qw(recursive learn sink_aliases resolver port address alias server_alias),
        ],
	object_states => [
	  $self => [ qw(_start _stop
                        query_handler sinkhole_response reply_handler
                   ) ],
	  $self => { _child => 'default', _parent => 'default' },
	],
  )->ID();
  return $self;
}

sub default { # {{{
  my ($self, $kernel, $heap, $session, $source, $dest) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0, ARG1];
} # }}}

sub query_handler {
  my ($self, $kernel, $heap, $session, $qname,$qclass,$qtype,$callback,$origin) = @_[OBJECT, KERNEL, HEAP, SESSION,ARG0..ARG4];
  my ($rcode, @ans, @auth, @add);

  # hashref accessible to all sinkhole "lookup" events - for cross-communication
  # that they can "fall through" early when a sinkhole has "answered" a request 
  my $oob_state = { handled => 0 };

  # send queries to sinkholes
  foreach my $sink_name (@{$heap->{greysink}->{sinks}}) {
    printf STDERR "Handler query_handler: Sink: %s, QO: %s QC: %s QT: %s QN: %s\n",$sink_name, $origin,$qclass,$qtype,$qname;
    # give the sinkhole a method to record its response, and tie it to the origin
    my $postback = $session->postback("sinkhole_response",$callback);
    # ask the sink to do a lookup, w/ the query + postback to respond through
    $kernel->post($sink_name,"lookup",$postback,$qname,$qclass,$qtype,$oob_state);
  }
  undef;
}

# this takes care of censoring data that shouldn't be in a response (e.g. recursive queries)
sub reply_handler {
  undef;
}

sub sinkhole_response {
  my ($self, $kernel, $heap, $session, $creation_args, $called_args) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0, ARG1];
  my ($callback) = @$creation_args;
  my ($rcode,$ans,$auth,$add,$header) = @$called_args;

  #print STDERR "Resolver Response:\n";
  #print Data::Dumper->Dump([$callback],[qw($callback)]);
  #print Data::Dumper->Dump([$rcode,$ans,$auth,$add,$header],[qw($rcode $ans $auth $add $header)]);
  #$session->post("reply_handler"
  $callback->($rcode, $ans, $auth, $add, { aa => 1 });
  # event listening for resolver postbacks - one event per resolver
  # stores status in _HEAP per socket/port pair and resolver friendly name
  # ARGS: resolver, hit?, record_ref
  # ... this needs to know how many/what names there are of resolvers.
}

sub _stop { # {{{
  print "Session ", $_[SESSION]->ID, " has stopped.\n";
} # }}}

sub _start {# {{{
  my ($self, $kernel, $heap, $session, %args) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0.. $#_];
  $kernel->alias_set($args{alias});
  printf "Greysink Session %d (%s) has started.\n", $session->ID, $args{alias};

  # save off our "child" sink aliases
  $heap->{greysink}->{sinks} = $args{sink_aliases};

  my $dns_server = POE::Component::Server::DNS->spawn(
    alias => $args{server_alias},
    no_clients => 1, # don't recurse, don't forward.
    map { defined($args{$_}) ? ($_ , $args{$_}) : () } qw(port address resolver_opts),
  );
  $heap->{greysink}->{dns_server} = $dns_server;

  # set up DNS listener handler
  $kernel->post(  $args{server_alias}, 'add_handler', {
      session => $args{alias},
      event => 'query_handler',
      label => 'ZA_WARUDO',
      match => '.',
  });
} # }}}
1;
