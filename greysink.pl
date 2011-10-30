#!/usr/bin/perl
# vim: foldmethod=marker filetype=perl ts=4 sw=2 commentstring=\ #\ %s

use strict;
use warnings;
use Net::DNS::Nameserver;
use Net::DNS::Resolver::Programmable;
use Net::DNS::Resolver;
use Tree::Trie;
use List::Util qw(first);

# (ab)use some unassigned RCODE values for our own internal use
# IGNORE/11 is an internal identifier for ::Resolver::Programmable resolver_code says "skip me please"
$Net::DNS::rcodesbyname{IGNORE} = 11;
%Net::DNS::rcodesbyval = reverse %Net::DNS::rcodesbyname;

# lifted from Net::DNS::Resolver::Programmable, and hacked up to support returning records in the additional/authority sections
package Net::DNS::Resolver::FullyProgrammable; # {{{
{
  use parent qw(Net::DNS::Resolver::Programmable);
  sub send { # {{{
      my $self = shift;

      my $query_packet = $self->make_query_packet(@_);
      my $question = ($query_packet->question)[0];
      my $domain   = lc($question->qname);
      my $rr_type  = $question->qtype;
      my $class    = $question->qclass;

      $self->_reset_errorstring;

      my ($rcode, $answer, $authority, $additional, $headermask );

      if (defined(my $resolver_code = $self->{resolver_code})) { # {{{
          ($rcode, $answer, $authority, $additional, $headermask ) = $resolver_code->($domain, $rr_type, $class);
      } # }}}

      if (not defined($rcode) or defined($Net::DNS::rcodesbyname{$rcode})) { # {{{
          # Valid RCODE, return a packet:
          $rcode = 'NOERROR' if not defined($rcode);

          if (defined(my $records = $self->{records})) { # {{{
              if (ref(my $rrs_for_domain = $records->{$domain}) eq 'ARRAY') {
                  foreach my $rr (@$rrs_for_domain) {
                      push(@$answer, $rr)
                          if  $rr->name  eq $domain
                          and $rr->type  eq $rr_type
                          and $rr->class eq $class;
                  }
              }
          } # }}}

          my $reply = Net::DNS::Packet->new($domain, $rr_type, $class);
          $reply->header->qr(1); # query response
          $reply->header->rcode($rcode);
          $reply->push(question => $query_packet->question); # query section returned to caller (?)
          # fill in the response body
          $reply->push(answer => @$answer) if $answer;
          $reply->push(authority => @$authority) if $authority;
          $reply->push(additional => @$additional) if $additional;

          $reply->header->aa(1) if $headermask->{'aa'};
          $reply->header->ra(1) if $headermask->{'ra'};
          $reply->header->ad(1) if $headermask->{'ad'};

          return $reply;
      } # }}}
      else { # {{{
          # Invalid RCODE, signal error condition by not returning a packet:
          $self->errorstring($rcode);
          return undef;
      } # }}}
  } # }}}
} # }}}

package main;

# shortcut for reversing a string
sub rev ($) { scalar reverse $_[0]; }

# debugging messages
my $verbose = 1;

# do we "learn" new zones hosted by nameservers in sinkholed zones?
# also: do we "learn" new nameservers for sinkholed zones?
my $auto_sinkhole = 1;
my $auto_whitelist = 1;

my $sinkhole_tree  = Tree::Trie->new({deepsearch=> "exact"});
my $whitelist_tree = Tree::Trie->new({deepsearch=> "exact"});

# RR record values are in Net::DNS::RR->new() (from string) format
# The script will replace * with the domain name queried.
# { records => { RR => '* string' } }
my $sinkhole_records = { # {{{
  records => {
    A  => '* 86400 IN A 10.1.2.3',
    NS => '* 86400 IN NS ns.sinkhole.example.com',
    SOA => '* 86400 IN SOA ns.sinkhole.example.com. cert.example.com.  ( 42 28800 14400 3600000 86400)',
  },
}; # }}}

# records for glue (authority) for NS
# ns.sinkhole.example.com == 192.168.100.100 here.
my $authorative_ns_records = { # {{{
  records => {
    A => '* 86400 IN A 192.168.100.100',
    NS => '* 86400 IN NS ns.sinkhole.example.com',
    SOA => '* 86400 IN SOA ns.sinkhole.example.com. cert.example.com.  ( 42 28800 14400 3600000 86400)',
  },
}; # }}}

# whitelist: don't add any records, only add domains - we will recurse out to the internet for the records {{{
#
# XXX FIXME: if we whitelist *one record* of a zone (e.g. www.richardharman.com, and not *.www.richardharman.com),
# and someone does a lookup for blar.www.richardharman.com,
# the real authorative NS gets leaked back to the client when in recusive mode.
#
# XXX FIXME: There's also a bug of the authorative NS getting leaked back
# when we whitelist third.second.tld, and there's an authorative NS for second.tld.
$whitelist_tree->add( rev('402ra.blogdns.com') );
$whitelist_tree->add( rev('www.richardharman.com') );
#$whitelist_tree->add( rev('ath.cx') );
# }}}

# sinkhole: pass a hashref of { records => { RR => 'rr string' } } # {{{
# XXX Note! x.com does not match *.x.com.  Wildcards are EXPLICIT, not implied.
$sinkhole_tree->add_data( rev('*.dyndns.org'), $sinkhole_records  );
$sinkhole_tree->add_data( rev('richardharman.com'), $sinkhole_records  );
$sinkhole_tree->add_data( rev('*.richardharman.com'), $sinkhole_records  );
# }}}

# authorative NS server records, for zones we're sinkholing.
$sinkhole_tree->add_data( rev('ns.sinkhole.example.com'),  $authorative_ns_records  );

my $recursive_resolver = Net::DNS::Resolver->new( # {{{
  recursive => 1,
  debug     => $verbose,
); # }}}

# programmable resolvers for filtering
# recursive - for communicating with the root DNS infrastructure
my $recursive = Net::DNS::Resolver::FullyProgrammable->new( # {{{
  resolver_code => \&recursive_handler,
); # }}}

# sinkhole - for runtime generating sinkholed responses
# to zones and/or nameservers we don't like
my $sinkhole = Net::DNS::Resolver::FullyProgrammable->new( # {{{
  resolver_code => \&sinkhole_handler,
); # }}}

# whitelist - for selectivly whitelisting things that otherwise
# would be sinkholed.  Note: uses $resolver for looking things up
my $whitelist = Net::DNS::Resolver::FullyProgrammable->new( # {{{
  resolver_code => \&whitelist_handler,
); # }}}

# resolvers - order matters here.  Priority first.
# first one to respond with an RCODE not equal to IGNORE is the response that gets sent to the client.
#
# XXX remove $recursive here if you don't want this nameserver to be an open dns server.
my @resolvers = ($whitelist,$sinkhole,$recursive);
#my @resolvers = ($whitelist,$sinkhole,);

# our nameserver object.  Query me w/ 'dig -p 5252 -t a mtfnpy.dyn.com @localhost'
my $ns = Net::DNS::Nameserver->new( # {{{
  LocalPort    => 5252,
  LocalAddr    => [ '127.0.0.1', ],
  ReplyHandler => \&reply_handler,
  Verbose      => $verbose,
) || die "couldn't create nameserver object ($!)"; # }}}

# find and return the first resolver's answer that has a RCODE not equal to IGNORE
sub first_response { # {{{
  my ($qname,$qtype,$qclass,$resolvers) = @_;

  foreach my $resolver (@$resolvers) {
    my $answer = $resolver->send( $qname, $qtype, $qclass );
    return $answer if ($answer->header->rcode ne "IGNORE");
  }

  # fall through default
  return undef;
} # }}}

# our handler for all incoming DNS requests.  Here's the brains.
sub reply_handler { # {{{
  my ( $qname, $qclass, $qtype, $peerhost, $query, $conn ) = @_;
  my ( $rcode, @ans, @auth, @add, $aa );

  # send requet to various resolvers.
  CENSOR_REDO: my $response = first_response($qname, $qtype, $qclass, \@resolvers);

  # $response might be undef if nothing responded
  if ($response) { # response was valid {{{
    $rcode = $response->header->rcode;
    @ans   = $response->answer;
    @add   = $response->additional;
    @auth  = $response->authority;
  } # }}}
  else { # none of our resolvers found anything {{{
    # return NXDOMAIN: because either the sinkhole/whitelist don't have the record
    # or the recursive resolver didn't find anything.
    $rcode = "NXDOMAIN";
  } # }}}

  # if our censorship check returns true, *and* we're learning,
  # we need to redo the lookup because it was wrong, and needs to be corrected.
  goto CENSOR_REDO if ( ($auto_sinkhole || $auto_whitelist) && censor_authority(\@auth,\@add) );
  # XXX FIXME RGH: We need to censor auth/add for whitelisted individual records,
  # so the real auth/add records don't get leaked back to the client.
  return ( $rcode, \@ans, \@auth, \@add , $aa );

} # }}}

# censor authority & additional records
sub censor_authority { # {{{
  my ($authority,$additional) = @_;

  foreach my $record (@$authority) { # {{{
    my @record_fields;

    # There's two types of records we get back in AUTHORITY sections.
    # NS and SOA.  But we treat them mostly the same.
    if ($record->type() eq 'NS')
    { @record_fields = qw(name nsdname); }

    elsif ($record->type() eq 'SOA')
    { @record_fields = qw(name mname); }

    my ($zone,$nameserver) = map { $record->$_() } @record_fields;

    # either the zone in $zone, or the nameserver in $nameserver could be something we're "authoritive" for.
    my $sinkholed_ns = lc( first { $sinkhole_tree->lookup( rev lc($_) ) } wildcardsearch($nameserver) );
    my $sinkholed_zone = lc( first { $sinkhole_tree->lookup( rev lc($_) ) } wildcardsearch($zone) );

    my $whitelisted_ns = lc( first { $whitelist_tree->lookup( rev lc($_) ) } wildcardsearch($nameserver) );
    my $whitelisted_zone = lc( first { $whitelist_tree->lookup( rev(lc($_)) ) } wildcardsearch($zone) );

    if ($whitelisted_zone) { # {{{
      # zone is whitelisted
      if (! $whitelisted_ns) { # {{{
        # ... but nameserver is not.
        # We should fake out that we're the only authorative NS for the zone,
        # so that other (potentially sinkholed) zones hosted by this nameserver
        # are inaccessible by clients unless they go through us for sinkhole checking.
        print STDERR "Warning: zone $zone is whitelisted under $whitelisted_zone, but its nameserver $nameserver is not.\n"
      } # }}}
      else { # {{{
        # ... and NS is whitelisted.
        # We're good.
        print STDERR "Info: zone $zone and ns $nameserver are both whitelisted.\n";
      } # }}}
    } # }}}
    else { # {{{
      # zone is not whitelisted
      if ( ! $whitelisted_ns ) { # {{{
        # ... and nameserver is not whitelisted
        # we should check sinkholes to see if the NS is sinkholed.
        print STDERR "Proceed carefully: zone $zone is not whitelisted, neither is its authorative NS $nameserver.  Sinkholes should be checked.\n";
      } # }}}
      else { # {{{
        # ... but nameserver is whitelisted.
        # we should check sinkholes to see if the zone is sinkholed.
        print STDERR "Warning: zone $zone is not whitelisted, but authorative NS $nameserver is whitelisted under $whitelisted_ns.\n";
        if ($auto_whitelist) { # {{{
		  clone_record($whitelist_tree,$zone,$whitelisted_ns);
		  clone_record($whitelist_tree,"*.".$zone,$whitelisted_ns);
          return 1;
        } # }}}
        # fall through to sinkhole ns/zone checking
      } # }}}
    } # }}}

    # if whitelisting had ANYTHING to do with the zone or nameserver, we should not have reached here.

    if ( $sinkholed_ns ) { # {{{
      if ( ! $sinkholed_zone) { # {{{
        # nameserver is sinkholed, but zoneis NOT sinkholed.
        # This is a new zone hosted by a sinkholed NS we don't know about.
        print STDERR "Critical: NS $nameserver in sinkholed zone $sinkholed_ns authorative for non-sinkholed (new?) zone $zone.\n";
        if ($auto_sinkhole) { # {{{
          clone_record($sinkhole_tree,$zone,$sinkholed_ns);
          clone_record($sinkhole_tree,"*.".$zone,$sinkholed_ns);
          return 1;
        } # }}}
      } # }}}
      else { # {{{
        # nameserver is sinkholed, and zone is sinkholed.
        # We're good.
        print STDERR "Info: NS $nameserver is is in sinkholed zone $sinkholed_ns and authorative for sinkholed zone $zone\n";
      } # }}}
    } # }}}
    else { # {{{
      if ( $sinkholed_zone ) { # {{{
        # nameserver is NOT sinkholed, but zone is sinkholed.
        # This is a new nameserver that we don't know about, for a sinkholed zone.
        print STDERR "Critical: (new?) NS $nameserver is authorative for sinkholed zone $zone, but $nameserver isn't sinkholed.\n";
        # XXX FIXME RGH: auto-sinkhole new nameserver?
        if ($auto_sinkhole) { # {{{
          clone_record($sinkhole_tree,$nameserver,$sinkholed_zone);
          return 1;
        } # }}}
      } # }}}
      else { # {{{
        # nameserver is NOT sinkholed, and zone is NOT sinkholed.
        print STDERR "Info: NS $nameserver not sinkholed hosting non-sinkholed zone $zone. Why are we here?\n";

        # Because we can't trust that these additional/authority records
        # will not conflict with a sinkholed zone, we really need to remove them.

        # kill the AUTHORITY records
        map { $_ = undef } @$authority;
        # kill the ADDITIONAL records
        map { $_ = undef } @$additional;
        return; # this is required, otherwise we'll try to iterate through undef objects above.
      } # }}}
    } # }}}
  } # }}}

  return;
} # }}}

# sinkhole resolver based on sinkhole trie - returns records from the sinkhole trie, or NXDOMAIN if the RR doesn't exist in the trie.
sub sinkhole_handler { # {{{
  my ( $qname, $qtype, $qclass ) = @_;
  my ( $rcode, @answer, @authority, @additional, $headermask );

  my $zone = first { $sinkhole_tree->lookup( rev lc($_) ) } wildcardsearch($qname);
  if ($zone) { # we found a record in our tree # {{{
    # grab the hashref that has our RR types & records
    my $record = $sinkhole_tree->lookup_data( rev lc($zone) );

    # check if the RR type we want exists
    if ( exists( $$record{records}{$qtype} ) ) { # RR exists, now we get to answer {{{
      # make our sinkholed response look like the question
      my $answer_rr = $record->{records}->{$qtype};
      $answer_rr =~ s/\*/$qname/g;
      # add the sinkholed RR to our answer section
      push @answer, Net::DNS::RR->new($answer_rr);

      # make a NS record for the authority section
      my $ns_rr = $record->{records}->{NS};
      $ns_rr =~ s/\*/$zone/g;
      # hide that we might be wildcarding stuff
      $ns_rr =~ s/^\*\.//g;
      # add the sinkholed NS to our authority section
      push @authority,Net::DNS::RR->new($ns_rr);

      # make an A record of the NS in the authority section for the additional section
      my $ns_name = $authority[0]->nsdname;

      # figure out what sinkholed "zone" the NS is in
      # XXX: this requires that the nameservers of sinkholed domains be in sinkholed domains!
      my $ns_zone = first { $sinkhole_tree->lookup( rev lc($_) ) } wildcardsearch($ns_name);
      # grab the records hashref for that zone
      my $ns_zone_records = $sinkhole_tree->lookup_data( rev lc($ns_zone) );
      # grab the A record in that hashref
      my $ns_a = $ns_zone_records->{records}->{A};
      # change the * to be the name of our nameserver
      $ns_a =~ s/\*/$ns_name/;
      # add the A record of our sinkholed NS to the additional section
      push @additional,Net::DNS::RR->new($ns_a);
      $rcode = "NOERROR";
    } # }}}
    else { # zone exists, but not the record we want. {{{
      $rcode = "NXDOMAIN";
    } # }}}
  } # }}}
  else { # we didn't find any records, so return custom rcode IGNORE {{{
    $rcode = "IGNORE";
  } # }}}

  return ( $rcode, \@answer, \@authority, \@additional, $headermask );
} # }}}

# whitelist resolver based on the whitelist trie - performs recursion for whitelisted records/zones
sub whitelist_handler { # {{{
  my ( $qname, $qtype, $qclass ) = @_;
  my ( $rcode, @answer, @authority, @additional, $headermask );

  my $zone = first { $whitelist_tree->lookup( rev lc($_) ) } wildcardsearch($qname);
  # $zone might be undef if no responses
  if ($zone) { # response was found {{{
    my $answer = $recursive_resolver->send( $qname, $qtype, $qclass );

    # clone the response
    $rcode        = $answer->header->rcode;
    @answer       = $answer->answer;
  } # }}}
  else { # no zone found in our trie, return custom rcode IGNORE {{{
    $rcode = "IGNORE";
  } # }}}

  return ( $rcode, \@answer, \@authority, \@additional, $headermask );
} # }}}

# handler for recursive queries (so we can remove authority/additional)
sub recursive_handler { # {{{
  my ( $qname, $qtype, $qclass ) = @_;
  print STDERR "recursive_handler: Q $qname $qtype $qclass\n";
  my ( $rcode, @answer, @authority, @additional, $headermask );

  my $answer = $recursive_resolver->send( $qname, $qtype, $qclass );

  # clone the response
  $rcode        = $answer->header->rcode;
  @answer       = $answer->answer;
  @additional   = $answer->additional;
  @authority    = $answer->authority;

  return ( $rcode, \@answer, \@authority, \@additional, $headermask );
} # }}}

# wildcard-ify a request to see if something shorter for a wildcard exists.
# This operates in a "most specific" to "least specific" order. {{{
# lookup for x.y.z.com == x.y.z.com, *.y.z.com, *.z.com, *.com
sub wildcardsearch {
  my ($domain) = @_;
  my @parts = reverse( split( m/\./, $domain ) );
  my @wildcards = reverse map { join( ".", '*', reverse( @parts[ 0 .. $_ ] ), ) } 0 .. $#parts - 1;
  return $domain, @wildcards;
} # }}}

# clone a record in a trie for a new key, mimicing an old key in the same trie
sub clone_record { # {{{
  my ($trie,$dest_zone,$source_zone) = @_;
  my $records = $trie->lookup_data( rev($source_zone) );
  print STDERR "Info: Learning new zone $dest_zone to sinkhole mimicing $source_zone\n";
  $trie->add_data( rev($dest_zone), $records );
} # }}}

$ns->main_loop;
