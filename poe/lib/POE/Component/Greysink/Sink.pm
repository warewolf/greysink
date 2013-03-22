# vim: foldmethod=marker
package POE::Component::Greysink::Sink;
use warnings;
use strict;
use POE;
use Data::Dumper;
use POEx::Inotify;
use Linux::Inotify2;
use Tree::Trie;
use List::Util qw(first);


sub spawn {#{{{
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
}#}}}

sub default {#{{{
  my ($self, $kernel, $heap, $session, $source, $dest) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0, ARG1];
}#}}}

# clone an existing Trie record to another one
sub learn {#{{{
  my ($self, $kernel, $heap, $session, $source, $dest) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0, ARG1];
}#}}}

sub list_change {#{{{
  my ($self, $kernel, $heap, $session, $e, $args) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0, ARG1];
  print "File ready: ", $e->fullname, "\n";
  print Data::Dumper->Dump([$args],[qw($args)]);
  $kernel->call($session,"load_data");
}#}}}

sub rev ($) { scalar reverse $_[0]; }

sub load_data {#{{{
  my ($self, $kernel, $heap, $session, %args ) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0..$#_];

  printf STDERR "Sink %s loading domains from %s\n",$heap->{alias},$heap->{list} if (-t);
  # set up Trie
  $heap->{trie} = Tree::Trie->new({deepsearch=> "exact"});
  open(my $list_fh,"<",$heap->{list}) or die "Couldn't open list file $heap->{list}";

  if (defined($heap->{records})) {
    # we have RRs for queries that match our Trie
    while (<$list_fh>) {
      chomp $_;
      print "Adding $_ with data\n";
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
}#}}}

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

sub sig_DIE {#{{{
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
}#}}}

sub _stop {#{{{
  print "Session ", $_[SESSION]->ID, " has stopped.\n";
}#}}}

sub collect_response {
  my ($self,$kernel,$heap,$session,$response) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0];
  print Data::Dumper->Dump([$response],[qw($response)]);
}

sub lookup {#{{{
  my ($self, $kernel, $heap, $session, $response_postback,$qname,$qclass,$qtype,$oob_state) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0..ARG5];
  my ($alias) = $kernel->alias_list($session);

  # answer data
  my ( $rcode, @answer, @authority, @additional, $headermask );

  printf STDERR "Lookup of %s in %s\n", $qname,$alias if (-t);

  if ($oob_state->{handled}) {
    printf STDERR "This request was handled by a previous sinkhole handler\n" if (-t);
    return undef;
  }

  # look for a hit in our Trie
  my $zone = first { $heap->{trie}->lookup( rev lc($_) ) } wildcardsearch($qname);

  if ($zone) {# we found a record in our trie
    printf STDERR "HIT: %s matches %s is in sink %s\n", $qname, $zone,$heap->{alias} if (-t);
    $oob_state->{handled}++;

    # retrieve the fake zone records from the Trie
    my $record = $heap->{trie}->lookup_data( rev lc($zone) );

    # check if the RR type asked for exists
    if ( exists ( $record->{$qtype} ) ) {

      # make our sinkholed response look like the questio
      my $answer_rr = $record->{$qtype};
      $answer_rr =~ s/\*/$qname/g;
      push @answer,Net::DNS::RR->new($answer_rr);

      # make a NS record for the authority section
      my $ns_rr = $heap->{authority}->{NS};
      $ns_rr =~ s/\*/$zone/;
      # hide that we might be wildcarding stuff
      $ns_rr =~ s/^\*\.//g;
      push @authority,Net::DNS::RR->new($ns_rr);

      # make an A record of the NS in the authority section for the additional section
      my $ns_name = $authority[0]->nsdname;
      print STDERR "ns name = $ns_name\n" if (-t);

      # figure out what sinkholed "zone" the NS is in
      # XXX: this requires that the nameservers of sinkholed domains be in sinkholed domains!
      my $ns_zone = first { $heap->{trie}->lookup( rev lc($_) ) } wildcardsearch($ns_name);
      # grab the records hashref for that zone
      my $ns_zone_records = $heap->{trie}->lookup_data( rev lc($ns_zone) );
      # grab the A record in that hashref
      my $ns_a = $ns_zone_records->{A};
      # change the * to be the name of our nameserver
      $ns_a =~ s/\*/$ns_name/;
      # add the A record of our sinkholed NS to the additional section
      push @additional,Net::DNS::RR->new($ns_a);
      $rcode = "NOERROR";

      $response_postback->($rcode, \@answer, \@authority, \@additional, { aa => 1 });

    } else {
      printf("Sink %s hit for domain %s, but RR type %s %s not found\n",$alias,$qname,$qclass,$qtype) if (-t);
    }
  } else {
    printf("Zone %s not found in %s\n",$qname,$alias) if (-t);
  }

  #print Data::Dumper->Dump([$response_postback,$qname,$qclass,$qtype],[qw($response_postback $qname $qclass $qtype)]);
}

# wildcard-ify a request to see if something shorter for a wildcard exists.
# This operates in a "most specific" to "least specific" order. {{{
# lookup for x.y.z.com == x.y.z.com, *.y.z.com, *.z.com, *.com
sub wildcardsearch {
  my ($domain) = @_;
  my @parts = reverse( split( m/\./, $domain ) );
  my @wildcards = reverse map { join( ".", '*', reverse( @parts[ 0 .. $_ ] ), ) } 0 .. $#parts - 1;
  return $domain, @wildcards;
} # }}}

1;
