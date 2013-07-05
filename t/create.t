#!perl -T
#
# Test creation of new password file

use strict;
use warnings;
use Test::More tests=>6;

my $dbfilename = 't/create_example.psafe3';

unlink($dbfilename) if -f $dbfilename;

require_ok('Crypt::PWSafe3');

my $vault = Crypt::PWSafe3->new(file=>$dbfilename, password=>"10101010");

ok( defined($vault), 'new() works');

my $count = 0;
foreach my $record($vault->getrecords()) {
    ++ $count;
}

ok($count == 0, 'new file is empty');

$vault->newrecord(
    group => "some group",
    title => "Hurrah, this is title",
    user => "John",
    passwd => "Very Secret password",
    notes => "Saved from test",
);
$vault->save();

ok(1, 'saved changes');

$count = 0;
my $the_record;
foreach my $record($vault->getrecords()) {
    ++ $count;
    $the_record = $record;
}

ok($count == 1, 'single record present after edits');

ok($the_record 
     && $the_record->group eq 'some group'
     && $the_record->title eq 'Hurrah, this is title'
     && $the_record->user eq 'John'
     && $the_record->passwd eq 'Very Secret password'
     && $the_record->notes eq 'Saved from test',
   "Saved record has proper values");

# cleanup
unlink($dbfilename);
