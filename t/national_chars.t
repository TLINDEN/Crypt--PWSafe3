#!perl -T
#
# Test of reading the file which contains some ugly characters inside

use strict;
use warnings;
use Test::More tests=>4;

my $dbfilename = 't/mekk.psafe3';

require_ok('Crypt::PWSafe3');

my $vault = Crypt::PWSafe3->new(file=>$dbfilename, password=>"10101010");

ok( defined($vault), 'new() opens');

my $count = 0;
foreach my $record($vault->getrecords()) {
    ++ $count;
}

ok($count == 2, 'some records found');

foreach my $record($vault->getrecords()) {
    $record->uuid;
    $record->title;
    $record->group;
    $record->user;
    $record->url;
    $record->passwd;
    $record->notes;
}

ok(1, 'read all fields');

