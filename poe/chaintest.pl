#!/usr/bin/perl
# vim: nolist filetype=perl foldmethod=marker
use strict;
use warnings;
use Data::Dumper;

use POE;

sub _stop {#{{{
  print "Session ", $_[SESSION]->ID, " has stopped.\n";
}#}}}

sub _start {#{{{
  my ($kernel, $heap, $session) = @_[KERNEL, HEAP, SESSION];
  print "Session ", $session->ID, " has started.\n";
  my $postback = $session->postback("complete","dns_connection_socketpair_maybe");
  my ($qname,$qclass,$qtype) = qw(foobar.com IN A);
  $kernel->yield('step_a',$qname,$qclass,$qtype,$postback);
}#}}}

sub complete {#{{{
  my ($kernel,$heap,$session,$passthru,$passback) = @_[KERNEL,HEAP, SESSION,ARG0,ARG1]; 
  print Data::Dumper->Dump([$passthru,$passback],[qw($passthru $passback)]);
}#}}}

sub step_a {#{{{
  my ($kernel,$heap,$session,$qname,$qclass,$qtype,$postback) = @_[KERNEL, HEAP, SESSION, ARG0..ARG3];
  if (rand()*10%2==0) {
    print "STEP A: Hit, we stop here.\n";
    $postback->($qname,$qclass,$qtype,"postback_arg3");
  } else {
    print "STEP A: Miss, we move down the chain\n";
    $kernel->yield('step_b',$qname,$qclass,$qtype,$postback);
  }
}#}}}

sub step_b {#{{{
  my ($kernel,$heap,$session,$qname,$qclass,$qtype,$postback) = @_[KERNEL, HEAP, SESSION, ARG0..ARG3];
  if (rand()*10%2==0) {
    print "STEP B: Hit, we stop here.\n";
    $postback->($qname,$qclass,$qtype,"postback_arg3");
  } else {
    print "STEP B: Miss, we move down the chain\n";
    $kernel->yield('step_c',$qname,$qclass,$qtype,$postback);
  }
}#}}}

sub step_c {#{{{
  my ($kernel,$heap,$session,$qname,$qclass,$qtype,$postback) = @_[KERNEL, HEAP, SESSION, ARG0..ARG3];
  print "STEP C: we stop here.\n";
  $postback->($qname,$qclass,$qtype,"postback_arg3");
}#}}}


POE::Session->create(
  inline_states => {
    _start    => \&_start,
    _stop     => \&_stop,
    complete => \&complete,
    step_a => \&step_a,
    step_b => \&step_b,
    step_c => \&step_c,
  }
);

POE::Kernel->run();
exit;
