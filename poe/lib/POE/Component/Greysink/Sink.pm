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
use List::Compare;
use Net::RNDC;
use File::Basename;

my $inotify_pattern = IN_CLOSE_WRITE;

sub rev ($) { scalar reverse $_[0]; }

sub spawn {#{{{
  my $class = shift;
  my %args = @_;
  my $self = bless { }, $class;

  $self->{session_id} = POE::Session->create(
        args => [
          map { defined($args{$_}) ? ( $_, $args{$_} ) : () } qw(resolver alias list inotify authority records rndc_key),
         ],
        object_states => [
          $self => [ qw(_start _stop generate_response list_change learn lookup sig_DIE load_data) ],
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

# call method, returns the zone that a qname is sinkholed in #{{{
sub lookup {
  my ($self, $kernel, $heap, $session, $qname) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0];
  my $zone = first { $heap->{trie}->lookup( rev lc($_) ) } wildcardsearch($qname);
  return $zone if $zone;
  return undef;
}#}}}

# add a new zone to the trie
sub learn {#{{{
  my ($self, $kernel, $heap, $session, $dest_zone) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0, ARG1];
  my $records = $heap->{records};
  #printf STDERR "Info: Learning new zone %s to sinkhole %s\n",$dest_zone,$heap->{alias};
  $heap->{trie}->add( rev($dest_zone));
  my $return = $heap->{rndc}->do(sprintf("flushname %s",$dest_zone));
  warn sprintf("flushname %s failed, %s",$dest_zone,$heap->{rndc}->error) if (!$return);
  return undef;
}#}}}

sub list_change {#{{{
  my ($self, $kernel, $heap, $session, $e, $args) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0, ARG1];
  return unless $e->fullname =~ qr/\/$args->{filename}$/;
  $kernel->call($session,"load_data","update");
}#}}}

sub load_data {#{{{
  my ($self, $kernel, $heap, $session, $mode ) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0];

  #printf STDERR "Sink %s loading domains from %s\n",$heap->{alias},$heap->{list};
  my ($filename,$path,$extension) = fileparse($heap->{list});

  # stop monitoring the directory temporarially
  $kernel->call( $heap->{inotify} => unmonitor => {#{{{
	      path => $path,
	      mask  => $inotify_pattern,
	      event => 'list_change',
	      args => { filename => $filename },
	   } );#}}}

  # set up Trie
  $heap->{new_trie} = Tree::Trie->new({deepsearch=> "exact"});
  open(my $list_fh,"<",$heap->{list}) or die "Couldn't open list file $heap->{list}";

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

    #printf STDERR "%s adding %s\n",$heap->{alias},$_;
    $heap->{new_trie}->add(rev($_));
    $heap->{new_trie}->add(rev("*.$_")) unless $_ =~ m/\*/;
  }

  if ($mode eq "update") {
    # compare old list to new list and flush those names from the cache
    my @old = $heap->{trie}->lookup("");
    my @new = $heap->{new_trie}->lookup("");
    my $lc = List::Compare->new('-u','-a',\@old,\@new);
    my @removed = $lc->get_Lonly();
    my @added = $lc->get_Ronly();

    foreach my $zone (@removed,@added) {
      my $return = $heap->{rndc}->do(sprintf("flushname %s",rev($zone)));
      #printf STDERR "Flushing %s\n",rev($zone);
      warn sprintf("flushname %s failed, %s",rev($zone),$heap->{rndc}->error) if (!$return);
    }
  }
  # replace the old trie with the new one
  $heap->{trie} = $heap->{new_trie};
  #print Data::Dumper->Dump([$heap->{trie}],[qw($trie)]);
  close $list_fh;

  # Resume monitoring directory for list changes now that we're done loading data
  $kernel->call( $heap->{inotify} => monitor => {#{{{
	      path => $path,
	      mask  => $inotify_pattern,
	      event => 'list_change',
	      args => { filename => $filename },
	   } );#}}}
}#}}}

sub _start {#{{{
  my ($self, $kernel, $heap, $session, %args ) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0..$#_];

  $kernel->alias_set($args{alias});
  #print STDERR "Sink Session ($args{alias}) ", $session->ID, " has started.\n";
  $poe_kernel->sig( DIE => 'sig_DIE' );

  $heap->{rndc} = Net::RNDC->new( host => '127.0.0.1', port => 953, key => $args{rndc_key});

  # save off what list file we're watching for load_data
  $heap->{list} = $args{list};

  # save off the inotify session alias
  $heap->{inotify} = $args{inotify};

  # remember records and authority records, if they exist
  if ($args{authority}) {
    $heap->{authority} = $args{authority};
  }

  if ($args{records}) {
    $heap->{records} = $args{records};
  }
  # set up and populate trie
  $kernel->call($session => "load_data","initial");

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
  #print STDERR "Session ", $_[SESSION]->ID, " has stopped.\n";
}#}}}

sub generate_response {#{{{
  my ($self, $kernel, $heap, $session, $response_postback,$qname,$qclass,$qtype,$oob_state) = @_[OBJECT, KERNEL, HEAP, SESSION, ARG0..ARG5];
  my ($alias) = $kernel->alias_list($session);

  # answer data
  my ( $rcode, @answer, @authority, @additional, $headermask );

  #printf STDERR "Lookup of %s in %s\n", $qname,$alias;

  if ($oob_state->{handled}) {#{{{
    #printf STDERR "This request was handled by a previous sinkhole handler\n";
    return undef;
  }#}}}

  # look for a hit in our Trie
  my $zone = first { $heap->{trie}->lookup( rev lc($_) ) } wildcardsearch($qname);

  if ($zone) { #{{{
    # we found a record in our trie
    #printf STDERR "HIT: %s matches %s is in sink %s\n", $qname, $zone,$heap->{alias};
    $oob_state->{handled}++;

    # retrieve the fake zone records from the Trie
    my $record = $heap->{records};

    # check if the RR type asked for exists
    if ( exists ( $record->{$qtype} ) ) {#{{{

      # make our sinkholed response look like the question
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
      #print STDERR "ns name = $ns_name\n";

      # grab the A record in the authority hashref
      my $ns_a = $heap->{authority}->{A};

      # change the * to be the name of our nameserver
      $ns_a =~ s/\*/$ns_name/;

      # add the A record of our sinkholed NS to the additional section
      push @additional,Net::DNS::RR->new($ns_a);
      $rcode = "NOERROR";

      # XXX FIXME XXX we should set AA => 1 only for things we're authorative for
      $response_postback->($rcode, \@answer, \@authority, \@additional, { aa => 1 });

    }#}}}
    else {#{{{
      # XXX XXX we should probally log this case here.
      warn sprintf("Sink %s hit for domain %s, but RR type %s %s not found. Return NXDOMAIN.\n",$alias,$qname,$qclass,$qtype);
      # XXX FIXME XXX we should set AA => 1 only for things we're authorative for
      $response_postback->("NXDOMAIN", \@answer, \@authority, \@additional, { aa => 1 });
    }#}}}
  }#}}}
  else {#{{{
    #printf STDERR ("Zone %s not found in sink %s, do nothing.\n",$qname,$alias);
  }#}}}
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
