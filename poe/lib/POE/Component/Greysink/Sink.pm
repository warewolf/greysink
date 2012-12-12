package POE::Component::Greysink::Sink;
use warnings;
use strict;
use POE;

sub spawn {
  my $class = shift;
  my %args = @_;
  my $self = bless { }, $class;
  print Data::Dumper->Dump([\%args],[qw($args)]);

  $self->{session_id} = POE::Session->create(
        args => [ ],
        object_states => [
          $self => [ qw(_start _stop) ],
        ],
  );
  return $self;
}

sub _start {#{{{
  my ($self, $kernel, $heap, $session, $alias) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0];
  print "Session ", $session->ID, " has started.\n";
  $kernel->alias_set($alias);
  my $postback = $session->postback("complete","dns_connection_socketpair_maybe");
  my ($qname,$qclass,$qtype) = qw(foobar.com IN A);
  $kernel->yield('step_a',$qname,$qclass,$qtype,$postback);
}#}}}

sub _stop {#{{{
  print "Session ", $_[SESSION]->ID, " has stopped.\n";
}#}}}


1;
