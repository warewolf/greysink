#!/usr/bin/perl

use strict;
use warnings;

use POE;
use POEx::Inotify;
use Linux::Inotify2;
use Data::Dumper;

POEx::Inotify->spawn( alias=>'notify' );

POE::Session->create(
    package_states => [ 
            'main' => [ qw(_start notification) ],
    ],
);

$poe_kernel->run();
exit 0;

sub _start {
    my( $kernel, $heap ) = @_[ KERNEL, HEAP ];

    $kernel->post( 'notify' => monitor => {
            path => '.',
            mask  => IN_CLOSE_WRITE,
            event => 'notification',
            args => [ "argument_on_notification" ],
            session => "mtfnpy",
         } );
    return;  
}

sub notification {
    my( $kernel, $e, $args ) = @_[ KERNEL, ARG0, ARG1];
    print "File ready: ", $e->fullname, "\n";
    print Data::Dumper->Dump([$e],[qw($e)]);
    #$kernel->post( notify => 'shutdown' );
    return;
}
