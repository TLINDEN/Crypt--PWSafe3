#!perl -T
#
# testscript for Crypt::PWSafe3 Classes by Thomas Linden
#
# needs to be invoked using the command "make test" from
# the Crypt::PWSafe3 source directory.
#
# Under normal circumstances every test should succeed.


use Data::Dumper;
#use Test::More tests => 57;
use Test::More qw(no_plan);


### 1
# load module
BEGIN { use_ok "Crypt::PWSafe3"};
require_ok( 'Crypt::PWSafe3' );

### 2
# open vault and read in all records
eval {
  my $vault = new Crypt::PWSafe3(file => 't/tom.psafe3', password => 'tom');
  my @r = $vault->getrecords;
  my $got = 0;
  foreach my $rec (@r) {
    if ($rec->uuid) {
      $got++;
    }
  }
  if (! $got) {
    die "No records found in test database";
  }
};
ok(!$@, "open a pwsafe3 database");

### 3
# modify an existing record
my $uuid3;
my %rdata3;
my $rec3;
my %data3 = (
	     user   => 'u3',
	     passwd => 'p3',
	     group  => 'g3',
	     title  => 't3',
	     notes  => 'n3'
	     );
eval {
  my $vault3 = new Crypt::PWSafe3(file => 't/tom.psafe3', password => 'tom');
  foreach my $uuid ($vault3->looprecord) {
    $uuid3 = $uuid;
    $vault3->modifyrecord($uuid3, %data3);
    last;
  }
  $vault3->save(file=>'t/3.out');

  my $rvault3 = new Crypt::PWSafe3(file => 't/3.out', password => 'tom');
  $rec3       = $rvault3->getrecord($uuid3);
  
  foreach my $name (keys %data3) {
    $rdata3{$name} = $rec3->$name();
  }
};
ok(!$@, "read a pwsafe3 database and change a record ($@)");
is_deeply(\%data3, \%rdata3, "Change a record an check if changes persist after saving");


### 4
# re-use $rec3 and change it the oop way
my $rec4;
eval {
  my $vault4 = new Crypt::PWSafe3(file => 't/3.out', password => 'tom');
  $rec4      = $vault4->getrecord($uuid3);
 
  $rec4->user("u4");
  $rec4->passwd("p4");

  $vault4->addrecord($rec4);
  $vault4->markmodified();
  $vault4->save(file=>'t/4.out');

  my $rvault4 = new Crypt::PWSafe3(file => 't/4.out', password => 'tom');
  $rec4 = $rvault4->getrecord($uuid3);
  if ($rec4->user ne 'u4') {
    die "oop way record change failed";
  }
};
ok(!$@, "re-use record and change it the oop way\n" . $@ . "\n");


### 5 modify some header fields
eval {
  my $vault5 = new Crypt::PWSafe3(file => 't/tom.psafe3', password => 'tom');

  my $h3 = new Crypt::PWSafe3::HeaderField(name => 'savedonhost', value => 'localhost');

  $vault5->addheader($h3);
  $vault5->markmodified();
  $vault5->save(file=>'t/5.out');

  my $rvault5 = new Crypt::PWSafe3(file => 't/5.out', password => 'tom');

  if ($rvault5->getheader('savedonhost')->value() ne 'localhost') {
    die "header savedonhost not correct";
  }
};
ok(!$@, "modify some header fields ($@)");

### clean temporary files
unlink('t/3.out');
unlink('t/4.out');
unlink('t/5.out');
