# vim: foldmethod=marker
package POE::Component::Greysink::Whitelist;
use warnings;
use strict;
use POE;
use Data::Dumper;
use POEx::Inotify;
use Linux::Inotify2;
use Tree::Trie;
use List::Util qw(first);

sub rev ($) { scalar reverse $_[0]; }

sub spawn {#{{{
  my $class = shift;
  my %args = @_;
  my $self = bless { }, $class;
  print STDERR "Sink spawn args: \n",Data::Dumper->Dump([\%args],[qw($args)]);

  $self->{session_id} = POE::Session->create(
        args => [
          map { defined($args{$_}) ? ( $_, $args{$_} ) : () } qw(resolver alias list inotify),
         ],
        object_states => [
          $self => [ qw(_start _stop generate_response list_change lookup learn sig_DIE load_data async_response) ],
	  $self => { _child => 'default' },
        ],
        heap => { alias => $args{alias} },
  )->ID();
  return $self;
}#}}}

sub default {#{{{
  my ($self, $kernel, $heap, $session, $source, $dest) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0, ARG1];
  return undef;
}#}}}

# call method, returns the zone that a qname is sinkholed in
sub lookup {#{{{
  my ($self, $kernel, $heap, $session, $qname) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0];
  my $zone = first { $heap->{trie}->lookup( rev lc($_) ) } wildcardsearch($qname);
  return $zone if $zone;
  return undef;
}#}}}

# clone an existing Trie record to another one
sub learn {#{{{
  my ($self, $kernel, $heap, $session, $dest_zone, $source_zone) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0, ARG1];
  my $records = $heap->{trie}->lookup_data( rev($source_zone) );
  printf STDERR "Info: Learning new zone %s to sinkhole %s mimicing %s\n",$dest_zone,$source_zone,$heap->{alias} if (-t);
  $heap->{trie}->add_data( rev($dest_zone), $records );
  return undef;
}#}}}

sub list_change {#{{{
  my ($self, $kernel, $heap, $session, $e, $args) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0, ARG1];
  print STDERR "File ready: ", $e->fullname, "\n";
  $kernel->call($session,"load_data");
}#}}}

sub load_data {#{{{
  my ($self, $kernel, $heap, $session, %args ) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0..$#_];

  printf STDERR "Sink %s loading domains from %s\n",$heap->{alias},$heap->{list} if (-t);
  # set up Trie
  $heap->{trie} = Tree::Trie->new({deepsearch=> "exact"});
  open(my $list_fh,"<",$heap->{list}) or die "Couldn't open list file $heap->{list}";

  if (defined($heap->{records})) {#{{{
    # we have RRs for queries that match our Trie
    while (<$list_fh>) {
      chomp $_;

      # skip comments
      next if ($_ =~ m/^#/);

      # remove comments from end of line
      $_ =~ s/\s*#.*//;

      # remove whitespace
      $_ =~ s/^\s+//; $_ =~ s/\s+$//;

      # skip lines that are empty
      next unless length($_);

      # remove invalid characters
      $_ =~ s/[^_.*a-z0-9]//i;

      printf STDERR "%s adding %s with data\n",$heap->{alias},$_ if (-t);
      $heap->{trie}->add_data(rev($_),$heap->{records});
    }
  }#}}}
  else {#{{{
    # we don't have RRs for queries that match our Trie.  Therefore
    while (<$list_fh>) {#{{{
      chomp $_;
      printf STDERR "%s adding %s\n",$heap->{alias},$_;
      $heap->{trie}->add(rev($_));
    }#}}}
  }#}}}
  close $list_fh;
}#}}}

sub _start {#{{{
  my ($self, $kernel, $heap, $session, %args ) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0..$#_];

  $kernel->alias_set($args{alias});
  print STDERR "Sink Session ($args{alias}) ", $session->ID, " has started.\n";
  $poe_kernel->sig( DIE => 'sig_DIE' );

  # save off what list file we're watching for load_data
  $heap->{list} = $args{list};

  # save off resolver object
  $heap->{resolver} = $args{resolver};

  print STDERR "Setting up inotify of $args{list} in $args{inotify} session\n";
  $kernel->post( $args{inotify} => monitor => {
	      path => $args{list},
	      mask  => IN_CLOSE_WRITE,
	      event => 'list_change',
	      args => [ "argument_on_notification" ],
	   } );

  # set up and populate trie
  $kernel->call($session => "load_data");

  return undef;
}#}}}

sub sig_DIE {#{{{
  my( $poe_kernel, $sig, $ex ) = @_[ KERNEL, ARG0, ARG1 ];
  # $sig is 'DIE'
  # $ex is the exception hash
  warn "$$: error in $ex->{event}: $ex->{error_str}";
  $poe_kernel->sig_handled(); 
  # Send the signal to session that sent the original event.
  if( $ex->{source_session} ne $_[SESSION] ) {#{{{
    $poe_kernel->signal( $ex->{source_session}, 'DIE', $sig, $ex );
  }#}}}
  $poe_kernel->stop();
}#}}}

sub _stop {#{{{
  print STDERR "Session ", $_[SESSION]->ID, " has stopped.\n";
}#}}}

sub generate_response {#{{{
  my ($self, $kernel, $heap, $session, $response_postback,$qname,$qclass,$qtype,$oob_state) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0..ARG5];
  my ($alias) = $kernel->alias_list($session);

  # answer data
  my ( $rcode, @answer, @authority, @additional, $headermask );

  printf STDERR "Lookup of %s in %s\n", $qname,$alias if (-t);

  # XXX FIXME: Whitelist should always come first, does this really need to check OOB state? XXX FIXME
  if ($oob_state->{handled}) {#{{{
    printf STDERR "This request was handled by a previous sinkhole handler\n" if (-t);
    return undef;
  }#}}}

  # look for a hit in our Trie
  my $zone = first { $heap->{trie}->lookup( rev lc($_) ) } wildcardsearch($qname);

  if ($zone) {# we found a record in our trie#{{{
    printf STDERR "HIT: %s matches %s is in sink %s\n", $qname, $zone,$heap->{alias} if (-t);
    $oob_state->{handled}++;

    # POE::Component::Client::DNS can return results immediately (from cache) a hahsref
    # or will post the same hashref structure to a receiver event
    my $response = $heap->{resolver}->resolve(
      class => $qclass,
      type => $qtype,
      host => $qname,

      event => "async_response",
      context => $response_postback);

    # If data is returned from cache, act as if it wasn't, and just post it to our receiver.
    if ($response) {#{{{
      $kernel->yield("async_response",$response);
    }#}}}
  }#}}}
  else {#{{{
    printf STDERR ("Zone %s not found in sink %s, do nothing.\n",$qname,$alias) if (-t);
  }#}}}
}#}}}

sub async_response {#{{{
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

}#}}}
# wildcard-ify a request to see if something shorter for a wildcard exists.
# This operates in a "most specific" to "least specific" order. 
# lookup for x.y.z.com == x.y.z.com, *.y.z.com, *.z.com, *.com
sub wildcardsearch {#{{{
  my ($domain) = @_;
  my @parts = reverse( split( m/\./, $domain ) );
  my @wildcards = reverse map { join( ".", '*', reverse( @parts[ 0 .. $_ ] ), ) } 0 .. $#parts - 1;
  return $domain, @wildcards;
}#}}}

1;