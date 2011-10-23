#!/usr/bin/perl
# vim: foldmethod=marker filetype=perl ts=4 sw=2 commentstring=\ #\ %s

use strict;
use warnings;
use Net::DNS::Nameserver;
use Net::DNS::Resolver::Programmable;
use Net::DNS::Resolver;
use Trie::Domain::Store; # get from https://github.com/warewolf/Trie-Domain-Store
use List::Util qw(first);

my $verbose = 0;

my $sinkhole_tree  = Trie::Domain::Store->new();
my $whitelist_tree = Trie::Domain::Store->new();

# in Net::DNS::RR->new() (from string) format
# The script will replace * with the name domain name queried.
#
my $apt_records = {    # {{{
  A  => '* 86400 IN A 10.1.2.3',
  NS => '* IN NS xabean.net',
  SOA => '* IN SOA ns.apt.blackhole.example.com. cert.example.com.  ( 1997022700 28800 14400 3600000 86400)',
};    # }}}

# whitelist
$whitelist_tree->add('richardharman.com');
$whitelist_tree->add('*.richardharman.com');

# sinkhole
$sinkhole_tree->add('*.dyn.com')->{records} = $apt_records;
$sinkhole_tree->add('dyn.com')->{records}   = $apt_records;

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

# resolvers - order matters here.
# first one to respond is the response that gets sent to the client.
#my @resolvers = ($whitelist,$sinkhole,$recursive);
my @resolvers = ( $whitelist, $sinkhole, );

my $ns = Net::DNS::Nameserver->new( # {{{
  LocalPort    => 5252,
  LocalAddr    => [ '127.0.0.1', ],
  ReplyHandler => \&reply_handler,
  Verbose      => $verbose,
) || die "couldn't create nameserver object\n"; # }}}

sub reply_handler { # {{{
  my ( $qname, $qclass, $qtype, $peerhost, $query, $conn ) = @_;
  my ( $rcode, @ans, @auth, @add );

  # send requet to various resolvers
  my (@responses) = map { $_->send( $qname, $qtype, $qclass ) } @resolvers;

  # we only want the first response
  my $valid_answer = first { $_->header->ancount } @responses;

  # response might be undef if nothing responded
  if ($valid_answer) { # response was valid {{{
    $rcode = $valid_answer->header->rcode;
    @ans   = $valid_answer->answer;
    @add   = $valid_answer->additional;
    @auth  = $valid_answer->authority;
  } # }}}
  else { # none of our resolvers found anything {{{

    $rcode = "SERVFAIL";
  } # }}}

  # XXX FIXME We need to sanatise responses!
  # The glue records (@add) might override what we "know" to be the "truth"
  # (e.g. what we have blacklisted, and how to "get" there)
  return ( $rcode, \@ans, \@auth, \@add, );

} # }}}

sub sinkhole_handler { # {{{
  my ( $domain, $rr_type, $class ) = @_;
  my ( $result, $aa, @rrs );

  my $zone = first { $sinkhole_tree->seek( lc($_) ) } wildcardsearch($domain);
  if ($zone) { # we found a record in our tree # {{{
    # grab the hashref that has our RR types & records
    my $record = $sinkhole_tree->seek( lc($zone) );

    # check if the RR type we want exists
    if ( exists( $$record{records}{$rr_type} ) ) { # RR exists, now we get to answer {{{
      my $str = $record->{records}->{$rr_type};

      # make our sinkholed response look like the question
      $str =~ s/\*/$domain/;
      push @rrs, Net::DNS::RR->new($str);
      $result = "NOERROR";
    } # }}}
  } # }}}
  else { # we didn't find any records, so NXDOMAIN {{{
    $result = "NXDOMAIN";
  } # }}}

  # XXX FIXME
  # it would be nice if we could respond with additional RRs (for NS lookups)
  return ( $result, $aa, @rrs );
} # }}}

sub whitelist_handler { # {{{
  my ( $domain, $rr_type, $class ) = @_;
  my ( $result, $aa, @rrs );

  my $zone = first { $whitelist_tree->seek( lc($_) ) } wildcardsearch($domain);
  # $zone might be undef if no responses
  if ($zone) { # response was found {{{
    my $answer = $recursive->send( $domain, $rr_type, $class );

    # set RR Code
    $result = $answer->header->rcode;
    @rrs    = $answer->answer;
    $result = "NOERROR";
  } # }}}
  else { # no response, return SERVFAIL.  Hopefully DNS client will come back later. # {{{
    $result = "SERVFAIL";
  } # }}}

  return ( $result, $aa, @rrs );
} # }}}

sub wildcardsearch { # wildcard-ify a request to see if something shorter for a wildcard exists {{{
  my ($domain) = @_;
  my @parts = reverse( split( m/\./, $domain ) );
  my @wildcards = reverse map { join( ".", '*', reverse( @parts[ 0 .. $_ ] ), ) } 0 .. $#parts - 1;
  return $domain, @wildcards;
} # }}}

$ns->main_loop;
