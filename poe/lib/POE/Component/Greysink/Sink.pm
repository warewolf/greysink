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
  print "Sink spawn args: \n",Data::Dumper->Dump([\%args],[qw($args)]);

  $self->{session_id} = POE::Session->create(
        args => [
          map { defined($args{$_}) ? ( $_, $args{$_} ) : () } qw(resolver alias list inotify authority records),
         ],
        object_states => [
          $self => [ qw(_start _stop lookup list_change learn sig_DIE load_data) ],
	  $self => { _child => 'default' },
        ],
        heap => { alias => $args{alias} },
  )->ID();
  return $self;
}

sub default {
  my ($self, $kernel, $heap, $session, $source, $dest) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0, ARG1];
}

# clone an existing Trie record to another one
sub learn {
  my ($self, $kernel, $heap, $session, $source, $dest) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0, ARG1];
}

sub list_change {
  my ($self, $kernel, $heap, $session, $e, $args) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0, ARG1];
  print "File ready: ", $e->fullname, "\n";
  print Data::Dumper->Dump([$args],[qw($args)]);
  $kernel->call($session,"load_data");
}

sub rev ($) { scalar reverse $_[0]; }

sub load_data {
  my ($self, $kernel, $heap, $session, %args ) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0..$#_];


  # set up Trie
  $heap->{trie} = Tree::Trie->new({deepsearch=> "exact"});
  open(my $list_fh,"<",$heap->{list}) or die "Couldn't open list file $heap->{list}";

  if (defined($heap->{records})) {
    # we have RRs for queries that match our Trie
    while (<$list_fh>) {
      chomp $_;
      print "$heap->{alias} Adding $_ with data\n";
      $heap->{trie}->add_data(rev($_),$heap->{records});
    }
  } else {
    # we don't have RRs for queries that match our Trie.  Therefore
    while (<$list_fh>) {
      chomp $_;
      print "$heap->{alias} Adding $_\n";
      $heap->{trie}->add(rev($_));
    }
  }
  close $list_fh;
}

sub _start {#{{{
  my ($self, $kernel, $heap, $session, %args ) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0..$#_];

  $kernel->alias_set($args{alias});
  print "Sink Session ($args{alias}) ", $session->ID, " has started.\n";
  $poe_kernel->sig( DIE => 'sig_DIE' );

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

sub sig_DIE {
  my( $poe_kernel, $sig, $ex ) = @_[ KERNEL, ARG0, ARG1 ];
  # $sig is 'DIE'
  # $ex is the exception hash
  warn "$$: error in $ex->{event}: $ex->{error_str}";
  $poe_kernel->sig_handled();

  # Send the signal to session that sent the original event.
  if( $ex->{source_session} ne $_[SESSION] ) {
    $poe_kernel->signal( $ex->{source_session}, 'DIE', $sig, $ex );
  }
  $poe_kernel->stop();
}

sub _stop {#{{{
  print "Session ", $_[SESSION]->ID, " has stopped.\n";
}#}}}

sub collect_response {
  my ($self,$kernel,$heap,$session,$response) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0];
  print Data::Dumper->Dump([$response],[qw($response)]);
}

sub lookup {#{{{
  my ($self, $kernel, $heap, $session, $postback,$qname,$qclass,$qtype) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0..ARG4];
  my ($alias) = $kernel->alias_list($session);
  print "Lookup of $qname in $alias\n";
  $postback->($alias);
  print Data::Dumper->Dump([$postback,$qname,$qclass,$qtype],[qw($postback $qname $qclass $qtype)]);
}
1;
