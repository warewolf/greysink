# vim: foldmethod=marker ts=4 sw=2 commentstring=\ #\ %s
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
                        query_handler sinkhole_response censor_authority recursive_lookup async_recursive_response
                   ) ],
	  $self => { _child => 'default', _parent => 'default' },
	],
  )->ID();
  return $self;
}

sub default {
  my ($self, $kernel, $heap, $session, $source, $dest) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0, ARG1];
}

sub query_handler {
  my ($self, $kernel, $heap, $session, $qname,$qclass,$qtype,$callback,$origin) = @_[OBJECT, KERNEL, HEAP, SESSION,ARG0..ARG4];
  my ($rcode, @ans, @auth, @add);

  # hashref accessible to all sinkhole "lookup" events - for cross-communication
  # that they can "fall through" early when a sinkhole has "answered" a request 
  my $oob_state = { handled => 0 };
  my $postback = $session->postback("sinkhole_response",$callback);

  # send queries to sinkholes
  foreach my $sink_name (@{$heap->{greysink}->{sinks}}) {
    printf STDERR "Handler query_handler: Sink: %s, QO: %s QC: %s QT: %s QN: %s\n",$sink_name, $origin,$qclass,$qtype,$qname;
    # give the sinkhole a method to record its response, and tie it to the origin
    # ask the sink to do a lookup, w/ the query + postback to respond through
    $kernel->post($sink_name,"generate_response",$postback,$qname,$qclass,$qtype,$oob_state);
  }
  # do recursion if desired
  $kernel->yield("recursive_lookup",$postback,$qname,$qclass,$qtype,$oob_state) if ($heap->{recursive});
  undef;
}

sub recursive_lookup {
  my ($self, $kernel, $heap, $session, $response_postback,$qname,$qclass,$qtype,$oob_state) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0..ARG5];

  print STDERR "Performing recursive lookup\n" if (-t);
  if ($oob_state->{handled}) {
    printf STDERR "This request was handled by a previous sinkhole handler\n" if (-t);
    return undef;
  }

  my $response = $heap->{resolver}->resolve(
      class => $qclass,
      type => $qtype,
      host => $qname,

      event => "async_recursive_response",
      context => $response_postback);

    # If data is returned from cache, act as if it wasn't, and just post it to our receiver.
    if ($response) {
      $kernel->yield("async_recursive_response",$response);
    }
  return undef;
}

sub async_recursive_response {
  my ($self, $kernel, $heap, $session, $response) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0];
  my ( $rcode, @answer, @authority, @additional, $headermask );

  my $response_postback = $response->{context};
  my $answer = $response->{response};
  my $error = $response->{error}; # XXX FIXME RGH: CHECK FOR ERRORS!!! XXX FIXME

  # clone the response$
  $rcode        = $answer->header->rcode;
  @answer       = $answer->answer;
  @additional   = $answer->additional;
  @authority    = $answer->authority;

  # the response postback gets whitewashed, so it's ok to pass auth/add through.
  $response_postback->($rcode, \@answer, \@authority, \@additional, { aa => 1 });

}


sub censor_authority {
  my ($self, $kernel, $heap, $session, $callback, $rcode, $ans, $auth, $add,$headermask) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0..ARG5];

  # flag variable to see if we need to redo the query
  my $redo = 0;
  print Data::Dumper->Dump([$ans],[qw($answer)]);

  AUTH_LOOP: foreach my $record (@$auth) {

    my @record_fields;
    if ($record->type() eq 'NS')
    { @record_fields = qw(name nsdname); }
    elsif ($record->type() eq 'SOA')
    { @record_fields = qw(name mname); }

    my ($zone,$nameserver) = map { $record->$_() } @record_fields;

	foreach my $sink_name (@{$heap->{greysink}->{sinks}}) {
      my $sinkholed_ns = $kernel->call($sink_name,"lookup",$nameserver);
      my $sinkholed_zone = $kernel->call($sink_name,"lookup",$zone);

      if ($sinkholed_ns) {
        # nameserver is sinkholed
        if (! $sinkholed_zone) {
          # nameserver is sinkholed, but zone is NOT sinkholed.  Learn & sinkhole.
		  printf STDERR "NS %s is sinkholed, but zone %s is not.  Learn and redo\n",$nameserver,$zone;
		  $kernel->call($sink_name,"learn",$zone);
		  $kernel->call($sink_name,"learn","*.$zone");
          $redo++;
        }
		else {
		  # nameserver is sinkholed, so is zone.  All good, do nothing
        }
      }
	  else {
        # nameserver is NOT sinkholed
        if ( $sinkholed_zone) {
          # nameserver is NOT sinkholed, but zone IS sinkholed
		  # kill the AUTHORITY records
		  map { $_ = undef } @$auth;
		  # kill the ADDITIONAL records
		  map { $_ = undef } @$add;
        }
        else {
		  # nameserver is NOT sinkholed, zone is NOT sinkholed.
        }
      }
    }# 
  }
    continue {
      if ($redo) {
		print STDERR "Redo loop hit, breaking out and repeating.\n" if (-t);
		print Data::Dumper->Dump([$ans],[qw($ans)]);
        $kernel->call($session,"query_handler", (map { $ans->[0]->$_() } qw(name class type)), $callback,"0.0.0.0");
        last AUTH_LOOP;
      }
    }
    # if we're here, we had no problems.
    $callback->("NOERROR", $ans, $auth, $add, { aa => 1 }) if (!$redo);
}

sub sinkhole_response {
  my ($self, $kernel, $heap, $session, $creation_args, $called_args) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0, ARG1];
  my ($callback) = @$creation_args;
  my ($rcode,$ans,$auth,$add,$header) = @$called_args;

  # here we need to loop through our sinkholes and ask if they need to censor data.
  # query -> sinkhole(s) -> response data -> check censor(s) -> censored -> handler tells sink to learn -> redo query from top

  # XXX FIXME - tempoary code, this prevents "learning"
  $kernel->yield("censor_authority",$callback,$rcode, $ans, $auth, $add, { aa => 1 });
  #$callback->($rcode, $ans, $auth, $add, { aa => 1 });
  # XXX FIXME
  # event listening for resolver postbacks - one event per resolver
  # stores status in _HEAP per socket/port pair and resolver friendly name
  # ARGS: resolver, hit?, record_ref
  # ... this needs to know how many/what names there are of resolvers.
}

sub _stop {
  print "Session ", $_[SESSION]->ID, " has stopped.\n";
}

sub _start {# 
  my ($self, $kernel, $heap, $session, %args) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0.. $#_];
  $kernel->alias_set($args{alias});
  printf "Greysink Session %d (%s) has started.\n", $session->ID, $args{alias};

  # save off our "child" sink aliases
  $heap->{greysink}->{sinks} = $args{sink_aliases};

  $heap->{resolver} = $args{resolver};
  my $dns_server = POE::Component::Server::DNS->spawn(
    alias => $args{server_alias},
    no_clients => 1, # don't recurse, don't forward.
    map { defined($args{$_}) ? ($_ , $args{$_}) : () } qw(port address resolver_opts),
  );
  $heap->{greysink}->{dns_server} = $dns_server;
  $heap->{recursive} = $args{recursive};

  # set up DNS listener handler
  $kernel->post(  $args{server_alias}, 'add_handler', {
      session => $args{alias},
      event => 'query_handler',
      label => 'ZA_WARUDO',
      match => '.',
  });
}
1;
