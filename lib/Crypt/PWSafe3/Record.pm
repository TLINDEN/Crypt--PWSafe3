package Crypt::PWSafe3::Record;

use Carp::Heavy;
use Carp;
use Exporter ();
use vars qw(@ISA @EXPORT %map2name %map2type);

my %map2type = %Crypt::PWSafe3::Field::map2type;

my %map2name = %Crypt::PWSafe3::Field::map2name;

$Crypt::PWSafe3::Record::VERSION = '1.02';

foreach my $field (keys %map2type ) {
  eval  qq(
      *Crypt::PWSafe3::Record::$field = sub {
              my(\$this, \$arg) = \@_;
              if (\$arg) {
                return \$this->modifyfield("$field", \$arg);
              }
              else {
                return \$this->{field}->{$field}->{value};
              }
      }
    );
}

sub new {
  #
  # new record object
  my($this) = @_;
  my $class = ref($this) || $this;
  my $self = { };
  bless($self, $class);
  $self->{field} = ();

  # just in case this is a record to be filled by the user,
  # initialize it properly
  my $newuuid = $self->genuuid();
  $self->addfield(new Crypt::PWSafe3::Field(
					    name  => 'uuid',
					    raw   => $newuuid,
					   ));

  $self->addfield(new Crypt::PWSafe3::Field(
					    name  => 'ctime',
					    value => time,
					   ));

  $self->addfield(new Crypt::PWSafe3::Field(
					    name  => 'mtime',
					    value => time
					   ));
  
  $self->addfield(new Crypt::PWSafe3::Field(
					    name  => 'lastmod',
					    value => time
					   ));

  $self->addfield(new Crypt::PWSafe3::Field(
					    name  => 'passwd',
					    value => ''
					   ));

  $self->addfield(new Crypt::PWSafe3::Field(
					    name  => 'user',
					    value => ''
					   ));

  $self->addfield(new Crypt::PWSafe3::Field(
					    name  => 'title',
					    value => ''
					   ));

  return $self;
}

sub modifyfield {
  #
  # add or modify a record field
  my($this, $name, $value) = @_;
  if (exists $map2type{$name}) {
    my $type = $map2type{$name};
    my $field = new  Crypt::PWSafe3::Field(
					   type => $type,
					   value => $value
					  );
    # we are in fact just overwriting an eventually
    # existing field with a new one, instead of modifying
    # it, so we are using the conversion automatism in
    # Field::new()
    $this->addfield($field);

    # mark the record as modified
    $this->addfield(new Crypt::PWSafe3::Field(
					      name => 'mtime',
					      value => time
					     ));

    $this->addfield(new Crypt::PWSafe3::Field(
					      name  => "lastmod",
					      value => time
					     ));
    return $field;
  }
  else {
    croak "Unknown field $name";
  }
}

sub genuuid {
  #
  # generate a v4 uuid string
  my($this) = @_;
  my $ug    = new Data::UUID;
  my $uuid  = $ug->create();
  return $uuid;
}

sub addfield {
  #
  # add a field to the record
  my ($this, $field) = @_;
  $this->{field}->{ $map2name{$field->type} } = $field;
}

=head1 NAME

Crypt::PWSafe3::Record - Represents a Passwordsafe v3 data record

=head1 SYNOPSIS

 use Crypt::PWSafe3;
 my $record = $vault->getrecord($uuid);
 $record->title('t2');
 $record->passwd('foobar');
 print $record->notes;

=head1 DESCRIPTION

B<Crypt::PWSafe3::Record> represents a Passwordsafe v3 data record.
Each record consists of a number of fields of type B<Crypt::PWSafe3::Field>.
The class provides get/set methods to access the values of those
fields.

It is also possible to access the raw unencoded values of the fields
by accessing them directly, refer to L<Crypt::PWSafe3::Field> for more
details on this.

=head1 METHODS

=head2 B<uuid([string])>

Returns the UUID without argument. Sets the UUID if an argument
is given. Must be a hex representation of an L<Data::UUID> object.

This will be generated automatically for new records, so you
normally don't have to cope with.

=head2 B<user([string])>

Returns the username without argument. Sets the username
if an argument is given.

=head2 B<title([string])>

Returns the title without argument. Sets the title
if an argument is given.

=head2 B<passwd([string])>

Returns the password without argument. Sets the password
if an argument is given.

=head2 B<notes([string])>

Returns the notes without argument. Sets the notes
if an argument is given.

=head2 B<group([string])>

Returns the group without argument. Sets the group
if an argument is given.

Group hierarchy can be done by separating subgroups
by dot, eg:

 $record->group('accounts.banking');

=head2 B<ctime([time_t])>

Returns the creation time without argument. Sets the creation time
if an argument is given. Argument must be an integer timestamp
as returned by L<time()>.

This will be generated automatically for new records, so you
normally don't have to cope with.

=head2 B<atime([time_t])>

Returns the access time without argument. Sets the access time
if an argument is given. Argument must be an integer timestamp
as returned by L<time()>.

B<Crypt::PWSafe3> doesn't update the atime field currently. So if
you mind, do it yourself.

=head2 B<mtime([time_t])>

Returns the modification time without argument. Sets the modification time
if an argument is given. Argument must be an integer timestamp
as returned by L<time()>.

This will be generated automatically for modified records, so you
normally don't have to cope with.

=head2 B<lastmod([string])>

Returns the modification time without argument. Sets the modification time
if an argument is given. Argument must be an integer timestamp
as returned by L<time()>.

This will be generated automatically for modified records, so you
normally don't have to cope with.

I<Note: I don't really know, what's the difference to mtime,
so, I update both. If someone knows better, please tell me.>

=head2 B<url([string])>

Returns the url without argument. Sets the url
if an argument is given. The url must be in the well
known notation as:

 proto://host/path

=head2 B<pwhist([string])>

Returns the password history without argument. Sets the password history
if an argument is given.

B<Crypt::PWSafe3> doesn't update the pwhist field currently. So if
you mind, do it yourself. Refer to L<Crypt::PWSafe3::Databaseformat>
for more details.

=head2 B<pwpol([string])>

Returns the password policy without argument. Sets the password policy
if an argument is given.

B<Crypt::PWSafe3> doesn't update the pwpol field currently. So if
you mind, do it yourself. Refer to L<Crypt::PWSafe3::Databaseformat>
for more details.

=head2 B<pwexp([string])>

Returns the password expire time without argument. Sets the password expire time
if an argument is given.

B<Crypt::PWSafe3> doesn't update the pwexp field currently. So if
you mind, do it yourself. Refer to L<Crypt::PWSafe3::Databaseformat>
for more details.

=head1 MANDATORY FIELDS

B<Crypt::PWSafe3::Record> creates the following fields automatically
on creation, because those fields are mandatory:

B<uuid> will be generated using L<Data::UUID>.

B<user, password, title> will be set to the empty string.

B<ctime, atime, mtime, lastmod> will be set to current
time of creation time.

=head1 SEE ALSO

L<Crypt::PWSafe3>

=head1 AUTHOR

T. Linden <tlinden@cpan.org>

=head1 COPYRIGHT

Copyright (c) 2011 by T.Linden <tlinden@cpan.org>.
All rights reserved.

=head1 LICENSE

This program is free software; you can redistribute it
and/or modify it under the same terms as Perl itself.

=cut

1;
