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

# shortcut for reversing a string
sub rev ($) { scalar reverse $_[0]; }

# debugging messages
my $verbose = 1;

my $sinkhole_tree  = Tree::Trie->new();
my $whitelist_tree = Tree::Trie->new();

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
$whitelist_tree->add( rev('www.richardharman.com') );
# }}}

# sinkhole: pass a hashref of { records => { RR => 'rr string' } } # {{{
# XXX Note! x.com does not match *.x.com.  Wildcards are EXPLICIT, not implied.
$sinkhole_tree->add_data( rev('richardharman.com'),  $sinkhole_records  );
$sinkhole_tree->add_data( rev('*.richardharman.com'), $sinkhole_records  );
$sinkhole_tree->add_data( rev('dyn.com'),  $sinkhole_records  );
$sinkhole_tree->add_data( rev('*.dyn.com'), $sinkhole_records  );
# }}}

# authorative NS server records, for zones we're sinkholing.
# XXX FIXME: this will be more effective/useful when ::Resolver::Programmable supports additional/authority RRs.
$sinkhole_tree->add_data( rev('ns.sinkhole.example.com'),  $authorative_ns_records  );

my $recursive = Net::DNS::Resolver->new( # {{{
  recursive => 1,
  debug     => $verbose,
); # }}}

my $sinkhole = Net::DNS::Resolver::Programmable->new( # {{{
  resolver_code => \&sinkhole_handler,
); # }}}

my $whitelist = Net::DNS::Resolver::Programmable->new( # {{{
  resolver_code => \&whitelist_handler,
); # }}}

# resolvers - order matters here.  Priority first.
# first one to respond with an RCODE not equal to IGNORE is the response that gets sent to the client.
#
# XXX remove $recursive here if you don't want this nameserver to be an open dns server.
my @resolvers = ($whitelist,$sinkhole,$recursive);

# our nameserver object.  Query me w/ 'dig -p 5252 -t a mtfnpy.dyn.com @localhost'
my $ns = Net::DNS::Nameserver->new( # {{{
  LocalPort    => 5252,
  LocalAddr    => [ '127.0.0.1', ],
  ReplyHandler => \&reply_handler,
  Verbose      => $verbose,
) || die "couldn't create nameserver object ($!)"; # }}}

# our handler for all incoming DNS requests.  Here's the brains.
sub reply_handler { # {{{
  my ( $qname, $qclass, $qtype, $peerhost, $query, $conn ) = @_;
  my ( $rcode, @ans, @auth, @add, $aa );

  # send requet to various resolvers.
  # this will do the lookup, test the response, and if it is == IGNORE, set the response to undef.
  my $response;
  first { $response = $_->send( $qname, $qtype, $qclass ); $response->header->rcode ne "IGNORE" or $response = undef } @resolvers;

  # $response might be undef if nothing responded
  if ($response) { # response was valid {{{
    # XXX FIXME RGH: Net::DNS::Resolver::Programmable doesn't support sending additional or authorative records :(
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

  # XXX FIXME We need to sanatise responses!
  # The glue records (@add) might override what we "know" to be the "truth"
  # (e.g. what we have blacklisted, and how to "get" there)
  return ( $rcode, \@ans, \@auth, \@add, $aa );

} # }}}

sub sinkhole_handler { # {{{
  my ( $qname, $qtype, $qclass ) = @_;
  my ( $rcode, $aa, @rrs );

  my $zone = first { $sinkhole_tree->lookup( rev lc($_) ) } wildcardsearch($qname);
  if ($zone) { # we found a record in our tree # {{{
    # grab the hashref that has our RR types & records
    my $record = $sinkhole_tree->lookup_data( rev lc($zone) );

    # check if the RR type we want exists
    if ( exists( $$record{records}{$qtype} ) ) { # RR exists, now we get to answer {{{
      my $str = $record->{records}->{$qtype};

      # make our sinkholed response look like the question
      $str =~ s/\*/$qname/g;
      push @rrs, Net::DNS::RR->new($str);
      $rcode = "NOERROR";
    } # }}}
    else { # zone exists, but not the record we want. {{{
      $rcode = "NXDOMAIN";
    } # }}}
  } # }}}
  else { # we didn't find any records, so return custom rcode IGNORE {{{
    $rcode = "IGNORE";
  } # }}}

  # XXX FIXME
  # it would be nice if we could respond with additional RRs (for NS lookups)
  return ( $rcode, $aa, @rrs );
} # }}}

sub whitelist_handler { # {{{
  my ( $qname, $qtype, $qclass ) = @_;
  my ( $rcode, $aa, @rrs );

  my $zone = first { $whitelist_tree->lookup( rev lc($_) ) } wildcardsearch($qname);
  # $zone might be undef if no responses
  if ($zone) { # response was found {{{
    my $answer = $recursive->send( $qname, $qtype, $qclass );

    # set RR Code
    $rcode = $answer->header->rcode;
    @rrs   = $answer->answer;
    $rcode = "NOERROR";
  } # }}}
  else { # no zone found in our trie, return custom rcode IGNORE
    $rcode = "IGNORE";
  } # }}}

  return ( $rcode, $aa, @rrs );
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

$ns->main_loop;
