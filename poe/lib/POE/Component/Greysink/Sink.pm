package POE::Component::Greysink::Sink;
use warnings;
use strict;
use POE;
use Data::Dumper;

sub spawn {
  my $class = shift;
  my %args = @_;
  my $self = bless { }, $class;
  print Data::Dumper->Dump([\%args],[qw($args)]);

  $self->{session_id} = POE::Session->create(
        args => [ $args{alias} ],
        object_states => [
          $self => [ qw(_start _stop lookup) ],
        ],
  );
  return $self;
}

sub _start {#{{{
  my ($self, $kernel, $heap, $session, $alias) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0];
  print "Sink Session ($alias) ", $session->ID, " has started.\n";
  $kernel->alias_set($alias);
  my $postback = $session->postback("complete","dns_connection_socketpair_maybe");
  my ($qname,$qclass,$qtype) = qw(foobar.com IN A);
  $kernel->yield('step_a',$qname,$qclass,$qtype,$postback);
}#}}}

sub _stop {#{{{
  print "Session ", $_[SESSION]->ID, " has stopped.\n";
}#}}}

sub lookup {#{{{
  my ($self, $kernel, $heap, $session, $postback,$qname,$qclass,$qtype) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0..ARG4];
  my ($alias) = $kernel->alias_list($session);
  print "Lookup of $qname in $alias\n";
  print Data::Dumper->Dump([$postback,$qname,$qclass,$qtype],[qw($postback $qname $qclass $qtype)]);
  
}
1;
