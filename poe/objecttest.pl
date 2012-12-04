#!/usr/bin/perl

use strict;
use warnings;
use POE;
use lib qw(lib);
use POE::Component::Greysink;
use Data::Dumper;

my $greysink = POE::Component::Greysink->spawn();
print Data::Dumper->Dump([$greysink],[qw($greysink)]);
POE::Kernel->run();
