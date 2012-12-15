package POE::Component::Greysink::Sink;
use warnings;
use strict;
use POE;
use Data::Dumper;
use POEx::Inotify;
use Linux::Inotify2;
use Tree::Trie;
use List::Util qw(first);


sub spawn {
  my $class = shift;
  my %args = @_;
  my $self = bless { }, $class;
  print Data::Dumper->Dump([\%args],[qw($args)]);

  $self->{session_id} = POE::Session->create(
        args => [ %args, ],
        object_states => [
          $self => [ qw(_start _stop lookup list_change learn) ],
        ],
  );
  return $self;
}

# clone an existing Trie record to another one
sub learn {
  my ($self, $kernel, $heap, $session, $source, $dest) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0, ARG1];
}

sub list_change {
  my ($self, $kernel, $heap, $session, $e, $args) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0, ARG1];
  print "File ready: ", $e->fullname, "\n";
  $kernel->call($session,"load_data");
}

sub _start {#{{{
  my ($self, $kernel, $heap, $session, %args ) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0..$#_];

  print "Sink Session ($args{alias}) ", $session->ID, " has started.\n";
  $kernel->alias_set($args{alias});

  # save off what list file we're watching for load_data
  $heap->{list} = $args{list};

  print "Setting up inotify of $args{list} in $args{inotify} session\n";
  $kernel->post( $args{inotify} => monitor => {
	      path => $args{list},
	      mask  => IN_CLOSE_WRITE,
	      event => 'list_change',
	      args => [ "argument_on_notification" ],
	   } );

  # remember records and authority records, if they exist
  if ($args{authority}) {
    $heap->{authority} = $args{authority};
  }

  if ($args{records}) {
    $heap->{records} = $args{records};
  }
  # set up and populate trie
  $kernel->call($session => "load_data");
}#}}}

sub load_data {
  my ($self, $kernel, $heap, $session, %args ) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0..$#_];

  # set up Trie
  $heap->{trie} = Tree::Trie->new({deepsearch=> "exact"});
  open(LIST,"<",$heap->{list}) or die "Couldn't open list file $heap->{list}";
  # open 
}

sub _stop {#{{{
  print "Session ", $_[SESSION]->ID, " has stopped.\n";
}#}}}

sub lookup {#{{{
  my ($self, $kernel, $heap, $session, $postback,$qname,$qclass,$qtype) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0..ARG4];
  my ($alias) = $kernel->alias_list($session);
  print "Lookup of $qname in $alias\n";
  $postback->("lookup response from $alias");
  print Data::Dumper->Dump([$postback,$qname,$qclass,$qtype],[qw($postback $qname $qclass $qtype)]);
  
}
1;
