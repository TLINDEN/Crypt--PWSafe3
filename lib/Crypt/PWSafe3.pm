
# http://passwordsafe.svn.sourceforge.net/viewvc/passwordsafe/trunk/pwsafe/pwsafe/docs/formatV3.txt?revision=2139

package Crypt::PWSafe3;

use strict;

use Carp::Heavy;
use Carp;

use Crypt::CBC;
use Crypt::ECB;
use Crypt::Twofish;
use Digest::HMAC;
use Digest::SHA;
use Crypt::Random qw( makerandom );
use Data::UUID;
use File::Copy qw(copy move);
use File::Spec;
use FileHandle;
use Data::Dumper;
use Exporter ();
use vars qw(@ISA @EXPORT);

$Crypt::PWSafe3::VERSION = '1.08';

use Crypt::PWSafe3::Field;
use Crypt::PWSafe3::HeaderField;
use Crypt::PWSafe3::Record;
use Crypt::PWSafe3::SHA256;

require 5.10.0;

#
# check, which random source to use.
# install a wrapper closure around the
# one we found.
BEGIN {
  eval { 
      require Bytes::Random::Secure;
      Bytes::Random::Secure->import("random_bytes");
  };
  if ($@) {
    # well, didn' work, use slow function
    eval { require Crypt::Random; };# qw( makerandom ); };
    if ($@) {
      croak "Could not find either Crypt::Random or Bytes::Random::Secure. Install one of them and retry!";
    }
    else {
      *Crypt::PWSafe3::random = sub {
	my($this, $len) = @_;
	my $bits = makerandom(Size => 256, Strength => 1);
	return substr($bits, 0, $len);
      };
    }
  }
  else {
    # good. use the faster one
    *Crypt::PWSafe3::random = sub {
      my($this, $len) = @_;
      return random_bytes($len);
    };
  }
}

my @fields = qw(tag salt iter shaps b1 b2 b3 b4 keyk file program
		keyl iv hmac header strechedpw password whoami);
foreach my $field (@fields) {
  eval  qq(
      *Crypt::PWSafe3::$field = sub {
              my(\$this, \$arg) = \@_;
              if (\$arg) {
                return \$this->{$field} = \$arg;
              }
              else {
                return \$this->{$field};
              }
      }
    );
}

sub new {
  #
  # new vault object
  my($this, %param) = @_;
  my $class = ref($this) || $this;
  my $self = \%param; # file, password, whoami, program
  bless($self, $class);

  # sanity checks
  if (! exists $self->{whoami}) {
    $self->{whoami} = $ENV{USER};
  }

  if (! exists $self->{program}) {
    $self->{program} = $0;
  }

  if (! exists $self->{password}) {
    croak 'Parameter password is required';
  }

  if (! exists $self->{file}) {
    $self->{file} = '';
    $self->create();
  }
  else {
    if (! -s $self->{file}) {
      $self->create();
    }
    else {
      $self->read();
    }
  }

  $self->{modified} = 0;

  return $self;
}

sub stretchpw {
  #
  # generate the streched password hash
  #
  # algorithm is described here:
  # [KEYSTRETCH Section 4.1] http://www.schneier.com/paper-low-entropy.pdf
  my ($this, $passwd) = @_;
  my $sha = new Digest::SHA('SHA-256');
  $sha->reset();
  $sha->add( ( $passwd, $this->salt) );
  my $stretched = $sha->digest();
  foreach (1 .. $this->iter) {
    $sha->reset();
    $sha->add( ( $stretched) );
    $stretched = $sha->digest();
  }
  $passwd = $this->random(64);
  return $stretched;
}

sub create {
  #
  # create an empty vault without writing to disk
  my($this) = @_;

  # default header fields
  $this->tag('PWS3');
  $this->salt($this->random(32));
  $this->iter(2048);

  # the streched pw
  $this->strechedpw($this->stretchpw($this->password()));

  # generate hash of the streched pw
  my $sha = new Digest::SHA('SHA-256');
  $sha->reset();
  $sha->add( ( $this->strechedpw() ) );
  $this->shaps( $sha->digest() );

  # encrypt b1 .. b4
  my $crypt = Crypt::ECB->new;
  #$crypt->padding(PADDING_AUTO);
  $crypt->cipher('Twofish');
  $crypt->key( $this->strechedpw() );
  $this->b1( $crypt->encrypt( $this->random(16) ) );
  $this->b2( $crypt->encrypt( $this->random(16) ) );
  $this->b3( $crypt->encrypt( $this->random(16) ) );
  $this->b4( $crypt->encrypt( $this->random(16) ) );

  # create key k + l
  $this->keyk( $crypt->decrypt( $this->b1() ) . $crypt->decrypt( $this->b2() ));
  $this->keyl( $crypt->decrypt( $this->b3() ) . $crypt->decrypt( $this->b4() ));

  # create IV
  $this->iv( $this->random(16) );

  # create hmac'er and cipher for actual encryption
  $this->{hmacer} = new Digest::HMAC($this->keyl, "Crypt::PWSafe3::SHA256");
  $this->{cipher} = new Crypt::CBC(
				   -key    => $this->keyk,
				   -iv     => $this->iv,
				   -cipher => 'Twofish',
				   -header => 'none',
				   -padding => 'null',
				   -literal_key => 1,
				   -keysize => 32,
				   -blocksize => 16
				  );

  # empty for now
  $this->hmac( $this->{hmacer}->digest() );
}

sub read {
  #
  # read and decrypt an existing vault file
  my($this) = @_;

  my $fd = new FileHandle($this->file, 'r');
  $fd->binmode();
  $this->{fd} = $fd;

  $this->tag( $this->readbytes(4) );
  if ($this->tag ne 'PWS3') {
    croak "Not a PasswordSave V3 file!";
  }

  $this->salt( $this->readbytes(32) );
  $this->iter( unpack("L<", $this->readbytes(4) ) );

  $this->strechedpw($this->stretchpw($this->password()));

  my $sha = new Digest::SHA(256);
  $sha->reset();
  $sha->add( ( $this->strechedpw() ) );
  $this->shaps( $sha->digest() );

  my $fileshaps = $this->readbytes(32);
  #print "sha1: <" . unpack('H*', $fileshaps) . ">\nsha2: <" . unpack('H*', $this->shaps) . ">\n";
  if ($fileshaps ne $this->shaps) {
    croak "Wrong password!";
  }

  $this->b1( $this->readbytes(16) );
  $this->b2( $this->readbytes(16) );
  $this->b3( $this->readbytes(16) );
  $this->b4( $this->readbytes(16) );

  my $crypt = Crypt::ECB->new;
  $crypt->cipher('Twofish') || die $crypt->errstring;
  $crypt->key( $this->strechedpw() );

  $this->keyk($crypt->decrypt($this->b1) . $crypt->decrypt($this->b2));
  $this->keyl($crypt->decrypt($this->b3) . $crypt->decrypt($this->b4));

  #print "keyk:<" . unpack('H*',  $this->keyk) . ">\n";

  $this->iv( $this->readbytes(16) );

  # create hmac'er and cipher for actual encryption
  $this->{hmacer} = new Digest::HMAC($this->keyl, "Crypt::PWSafe3::SHA256");
  #print "keyk len: " . length($this->keyk) . "\n";
  $this->{cipher} = new Crypt::CBC(
				   -key    => $this->keyk,
				   -iv     => $this->iv,
				   -cipher => 'Twofish',
				   -header => 'none',
				   -padding => 'null',
				   -literal_key => 1,
				   -keysize => 32,
				   -blocksize => 16
				  );

  # read db header fields
  $this->{header} = {};
  while (1) {
    my $field = $this->readfield('header');
    if (! $field) {
      last;
    }
    if ($field->type == 0xff) {
      last;
    }
    $this->addheader($field);
    $this->hmacer($field->raw);
  }

  # read db records
  my $record = new Crypt::PWSafe3::Record();
  $this->{record} = {};
  while (1) {
    my $field = $this->readfield();
    if (! $field) {
      last;
    }
    if ($field->type == 0xff) {
      $this->addrecord($record);
      #print "--- record added (uuid:" . $record->uuid . ")\n";
      $record = new Crypt::PWSafe3::Record();
    }
    else {
      $record->addfield($field);
      $this->hmacer($field->raw);
    }
  }

  # read and check file hmac
  $this->hmac( $this->readbytes(32) );
  my $calcmac = $this->{hmacer}->digest();
  if ($calcmac ne $this->hmac) {
    croak "File integrity check failed";
  }

  $this->{fd}->close();
}


sub save {
  #
  # write data to the vault file
  my($this, %param) = @_;
  my($file, $passwd);

  if (! exists $param{file}) {
    $file = $this->file;
  }
  else {
    $file = $param{file}
  }
  if (! exists $param{passwd}) {
    $passwd = $this->password;
  }
  else {
    $passwd = $param{passwd}
  }

  if (! $this->{modified}) {
    return;
  }

  my $lastsave  = new Crypt::PWSafe3::HeaderField(type => 0x04, value => time);
  my $whatsaved = new Crypt::PWSafe3::HeaderField(type => 0x06, value => $this->{program});
  my $whosaved  = new Crypt::PWSafe3::HeaderField(type => 0x05, value => $this->{whoami});
  $this->addheader($lastsave);
  $this->addheader($whatsaved);
  $this->addheader($whosaved);

  my $tmpfile = File::Spec->catfile(File::Spec->tmpdir(),
				    ".vault-" . unpack("L<4", $this->random(16)));
  unlink $tmpfile;
  my $fd = new FileHandle($tmpfile, 'w') or croak "Could not open tmpfile $tmpfile: $!\n";
  $fd->binmode();
  $this->{fd} = $fd;

  $this->writebytes($this->tag);
  $this->writebytes($this->salt);
  $this->writebytes(pack("L<", $this->iter));

  $this->strechedpw($this->stretchpw($passwd));

  # line 472
  my $sha = new Digest::SHA(256);
  $sha->reset();
  $sha->add( ( $this->strechedpw() ) );
  $this->shaps( $sha->digest() );

  $this->writebytes($this->shaps);
  $this->writebytes($this->b1);
  $this->writebytes($this->b2);
  $this->writebytes($this->b3);
  $this->writebytes($this->b4);

  my $crypt = Crypt::ECB->new;
  $crypt->cipher('Twofish');
  $crypt->key( $this->strechedpw() );

  $this->keyk($crypt->decrypt($this->b1) . $crypt->decrypt($this->b2));
  $this->keyl($crypt->decrypt($this->b3) . $crypt->decrypt($this->b4));

  $this->writebytes($this->iv);

  $this->{hmacer} = new Digest::HMAC($this->keyl, "Crypt::PWSafe3::SHA256");
  $this->{cipher} = new Crypt::CBC(
				   -key    => $this->keyk,
				   -iv     => $this->iv,
				   -cipher => 'Twofish',
				   -header => 'none',
				   -padding => 'null',
				   -literal_key => 1,
				   -keysize => 32,
				   -blocksize => 16
				  );

  my $eof = new Crypt::PWSafe3::HeaderField(type => 0xff, value => '');

  foreach my $type (keys %{$this->{header}}) {
    $this->writefield($this->{header}->{$type});
    $this->hmacer($this->{header}->{$type}->{raw});
  }
  $this->writefield($eof);
  $this->hmacer($eof->{raw});

  $eof = new Crypt::PWSafe3::Field(type => 0xff, value => '');

  foreach my $uuid (keys %{$this->{record}}) {
    my $record = $this->{record}->{$uuid};
    foreach my $type (keys %{$record->{field}}) {
      $this->writefield($record->{field}->{$type});
      $this->hmacer($record->{field}->{$type}->{raw});
    }
    $this->writefield($eof);
    $this->hmacer($eof->{raw});
  }

  $this->writefield(new Crypt::PWSafe3::Field(type => 'none', raw => 0));

  $this->hmac( $this->{hmacer}->digest() );
  $this->writebytes($this->hmac);
  $this->{fd}->close();

  # now try to read it in again to check if it
  # is valid what we created
  eval {
    my $vault = new Crypt::PWSafe3(file => $tmpfile, password => $passwd);
  };
  if ($@) {
    unlink $tmpfile;
    croak "File integrity check failed ($@)";
  }
  else {
    # well, seems to be ok :)
    move($tmpfile, $file);
  }
}

sub writefield {
  #
  # write a field to vault file
  my($this, $field) = @_;

  #print "write field " . $field->name . "\n";

  if ($field->type eq 'none') {
    $this->writebytes("PWS3-EOFPWS3-EOF");
    return;
  }

  my $len  = pack("L<", $field->len);
  my $type = pack("C", $field->type);
  my $raw  = $field->raw;

  # Assemble TLV block and pad to 16-byte boundary
  my $data = $len . $type . $raw;

  if (length($data) % 16 != 0) {
    # too small or too large, padding required
    my $padcount = 16 - (length($data) % 16);
    $data .= $this->random($padcount);
  }

  if (length($data) > 16) {
    my $crypt;
    while (1) {
      #print "processing part\n";
      my $part = substr($data, 0, 16);
      $crypt .= $this->encrypt($part);
      if (length($data) <= 16) {
	#print "  this was the last one\n";
	last;
      }
      else {
	#print "  getting next\n";
	$data = substr($data, 16);
      }
    }
    #print "  len: " . length($crypt) . "\n";
    $this->writebytes($crypt);
  }
  else {
    $this->writebytes($this->encrypt($data));
  }
}

sub getrecord {
  #
  # return the given record
  my($this, $uuid) = @_;
  if (exists $this->{record}->{$uuid}) {
    return $this->{record}->{$uuid};
  }
  else {
    return 0;
  }
}

sub getrecords {
  #
  # return all records we've got as a copy
  my ($this) = @_;
  return map { $this->{record}->{$_} } keys %{$this->{record}};
}

sub looprecord {
  #
  # return a list of uuid's of all records
  my ($this) = @_;
  return keys %{$this->{record}};
}

sub modifyrecord {
  #
  # modify a record identified by the given uuid
  my($this, $uuid, %fields) = @_;

  if (! exists $this->{record}->{$uuid}) {
    croak "No record with uuid $uuid found!";
  }

  foreach my $field (keys %fields) {
    $this->{record}->{$uuid}->modifyfield($field, $fields{$field});
  }

  # mark vault as modified
  $this->markmodified();
}

sub deleterecord {
  #
  # delete a record identified by the given uuid, if present
  # 
  # returns 1 if record was actually removed, 0 if it was not present
  my($this, $uuid) = @_;

  if (! exists $this->{record}->{$uuid}) {
      return 0;
  }

  delete $this->{record}->{$uuid};

  # mark vault as modified
  $this->markmodified();

  return 1;
}


sub markmodified {
  #
  # mark the vault as modified by setting the appropriate header fields
  my($this) = @_;
  my $lastmod = new Crypt::PWSafe3::HeaderField(
						name  => "lastsavetime",
						value => time
						);
  my $who = new Crypt::PWSafe3::HeaderField(
						name  => "wholastsaved",
						value => $this->{whoami}
						);
  $this->addheader($lastmod);
  $this->addheader($who);
  $this->{modified} = 1;
}

sub newrecord {
  #
  # add a new record to an existing vault
  my($this, %fields) = @_;
  my $record = new Crypt::PWSafe3::Record();
  foreach my $field (keys %fields) {
    $record->modifyfield($field, $fields{$field});
  }
  $this->markmodified();
  $this->addrecord($record);
  return $record->uuid;
}

sub addrecord {
  #
  # add a record object to record hash
  my($this, $record) = @_;
  $this->{record}->{ $record->uuid } = $record;
}

sub addheader {
  #
  # add a header field to header hash
  my($this, $field) = @_;
  $this->{header}->{ $field->name } = $field;
}


sub readfield {
  #
  # read and return a field object of the vault
  my($this, $header) = @_;
  my $data = $this->readbytes(16);
  if (! $data or length($data) < 16) {
    croak "EOF encountered when parsing record field";
  }
  if ($data eq "PWS3-EOFPWS3-EOF") {
    return 0;
  }

  #print "\n  raw: <" . unpack('H*', $data) . ">\n";

  $data = $this->decrypt($data);

  #print "clear: <" . unpack('H*', $data) . ">\n";

  my $len  = unpack("L<", substr($data, 0, 4));
  my $type = unpack("C", substr($data, 4, 1));
  my $raw  = substr($data, 5);

  #print "readfield: len: $len, type: $type\n";

  if ($len > 11) {
    my $step = int(($len+4) / 16);
    for (1 .. $step) {
      my $data = $this->readbytes(16);
      if (! $data or length($data) < 16) {
	croak "EOF encountered when parsing record field";
      }
      $raw .= $this->decrypt($data);
    }
  }
  $raw = substr($raw, 0, $len);
  if ($header) {
    return new Crypt::PWSafe3::HeaderField(type => $type, raw => $raw);
  }
  else {
    return new Crypt::PWSafe3::Field(type => $type, raw => $raw);
  }
}

sub decrypt {
  #
  # helper, decrypt a string
  my ($this, $data) = @_;
  my $clear = $this->{cipher}->decrypt($data);
  $this->{cipher}->iv($data);
  return $clear;
}

sub encrypt {
  #
  # helper, encrypt a string
  my ($this, $data) = @_;
  my $raw = $this->{cipher}->encrypt($data);
  if (length($raw) > 16) {
    # we use only the last 16byte block as next iv
    # if data is more than 1 blocks than Crypt::CBC
    # has already updated the iv for the inner blocks
    $raw = substr($raw, -16, 16);
  }
  $this->{cipher}->iv($raw);
  return $raw;
}

sub hmacer {
  #
  # helper, hmac generator
  my($this, $data) = @_;

  $this->{hmacer}->add($data);
}

sub readbytes {
  #
  # helper, reads number of bytes
  my ($this, $size) = @_;
  my $buffer;
  my ($package, $filename, $line) = caller;

  my $got = $this->{fd}->sysread($buffer, $size);
  if ($got == $size) {
    $this->{sum} += $got;
    #print "Got $got bytes (read so far: $this->{sum} bytes) $package line $line\n";
    return $buffer;
  }
  else {
    return 0;
  }
}

sub writebytes {
  #
  # helper, reads number of bytes
  my ($this, $bytes) = @_;
  my $got = $this->{fd}->syswrite($bytes);
  if ($got) {
    return $got;
  }
  else {
    croak "Could not write to $this->{file}: $!";
  }
}


sub getheader {
  #
  # return a header object
  my($this, $name) = @_;
  #   $this->{header}->{ $field->name } = $field;
  if (exists  $this->{header}->{$name}) {
    return $this->{header}->{$name};
  }
  else {
    croak "Unknown header $name";
  }
}




=head1 NAME

Crypt::PWSafe3 - Read and write Passwordsafe v3 files

=head1 SYNOPSIS

 use Crypt::PWSafe3;
 my $vault = new Crypt::PWSafe3(file => 'filename.psafe3', password => 'somesecret');
 
 # fetch all database records
 my @records = $vault->getrecords();
 foreach my $record (@records) {
   print $record->uuid;
   print $record->title;
   print $record->passwd;
   # see Crypt::PWSafe3::Record for more details on accessing records
 }

 # same as above but don't detach records from vault
 foreach my $uuid ($vault->looprecord) {
   # either change a record
   $vault->modifyrecord($uuid, passwd => 'p1');

   # or just access it directly
   print $vault->{record}->{$uuid}->title;
 }

 # add a new record
 $vault->newrecord(user => 'u1', passwd => 'p1', title => 't1');

 # modify an existing record
 $vault->modifyrecord($uuid, passwd => 'p1');

 # replace a record (aka edit it)
 my $record = $vault->getrecord($uuid);
 $record->title('t2');
 $record->passwd('foobar');
 $vault->addrecord($record);

 # mark the vault as modified (not required if
 # changes were done with ::modifyrecord()
 $vault->markmodified();

 # save the vault
 $vault->save();

 # save it under another name using another password
 $vault->save(file => 'another.pwsafe3', passwd => 'blah'); 

 # access database headers
 print $vault->getheader('wholastsaved')->value();
 print scalar localtime($vault->getheader('lastsavetime')->value());

 # add/replace a database header
 my $h = new Crypt::PWSafe3::HeaderField(name => 'savedonhost', value => 'localhost');
 $vault->addheader($h);

=head1 DESCRIPTION

Crypt::PWSafe3 provides read and write access to password
database files created by Password Safe V3 (and up) available at
http://passwordsafe.sf.net.

=head1 METHODS

=head2 B<new()>

The new() method creates a new Crypt::PWSafe3 object. Any parameters
must be given as hash parameters.

 my $vault = new Crypt::PWSafe3(
                     file     => 'vault.psafe3',
                     password => 'secret',
                     whoami   => 'user1',
                     program  => 'mypwtool v1'
 );

Mandatory parameters:

=over

=item B<file>

Specifies the password safe (v3) file. If it exists
it will be read in. Otherwise it will be created
if you call B<save()>.

=item B<password>

The password required to decrypt the password safe file.

=back

Optional parameters:

=over

=item B<whoami>

Specifies the user who saves the password safe file.
If omitted the environment variable USER will be used
when calling B<save()>.

=item B<program>

Specifies which program saved the password safe file.
If omitted, the content of the perl variable $0 will
be used, which contains the name of the current running
script.

=back

The optional parameters will become header fields of
the password safe file. You can manually set/override
more headers. See section L<addheader()> for
more details.

=head2 B<getrecords()>

Returns a list of all records found in the password
safe file. Each element is an B<Crypt::PWSafe3::Record>
object.

A record object is identified by its B<UUID4> value,
which is a unique identifier. You can access the uuid by:

 $record->uuid

Accessing other record properties works the same. For
more details, refer to L<Crypt::PWSafe3::Record>.

Please note that record objects accessed this way are
copies. If you change such a record object and save the
database, nothing will in fact change. In this case you
need to put the changed record back into the record
list of the Crypt::PWSafe3 object by:

 $vault->addrecord($record):

See section L<addrecord()> for more details on this.


=head2 B<looprecord()>

Returns a list of UUIDs of all known records. You can
use this list to iterate over the records without
copying them and optionally changing them in place.

Example:

 foreach my $uuid ($vault->looprecord) {
   # either change a record
   $vault->modifyrecord($uuid, passwd => 'p1');

   # or just access it directly
   print $vault->{record}->{$uuid}->title;
 }


=head2 B<modifyrecord(uuid, parameter-hash)>

Modifies the record identified by the given UUID using
the values of the supplied parameter hash.

Example:

   $vault->modifyrecord($uuid, passwd => 'p1');

The parameter hash may contain any valid record field
type with according values. Refer to L<Crypt::PWSafe3::Record>
for details about available fields.


=head2 B<deleterecord(uuid)>

Delete the record identified by the given UUID.

=head2 B<save([parameter-hash])>

Save the current password safe vault back to disk.

If not otherwise specified, use the same file and
password as we used to open it initially. If the
file doesn't exist it will be created.

You may specify another filename and password here
by using a parameter hash.

Example:

 $vault->save(file => 'anotherfile.psafe3', passwd => 'foo');

Please note, that the vault will be written to a
temporary file first, then this temporary file
will be read in and if that works, it will be
moved over the destination file. This way the original
file persists if the written database gets corrupted
by some unknown reason (a bug for instance).


=head2 B<getheader(name)>

Returns a raw B<Crypt::PWSafe3::HeaderField> object.
Refer to L<Crypt::PWSafe3::HeaderField> for details
how to access it.

=head2 B<addheader(object)>

Adds a header field to the password safe database. The
object parameter must be an B<Crypt::PWSafe3::HeaderField>
object.

If the header already exists it will be replaced.

Refer to L<Crypt::PWSafe3::HeaderField> for details
how to create new ones
.

=head1 AUTHOR

T. Linden <tlinden@cpan.org>

=head1 BUGS

Report bugs to
http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Crypt-PWSafe3.


=head1 SEE ALSO

Subclasses:

L<Crypt::PWSafe3::Record>
L<Crypt::PWSafe3::Field>
L<Crypt::PWSafe3::HeaderField>

Password Safe Homepage:
L<http://passwordsafe.sourceforge.net/>

Another (read-only) perl module:
L<Crypt::Pwsafe>

A python port of Password Safe:
L<http://www.christoph-sommer.de/loxodo/>
Many thanks to Christoph Sommer, his python library
inspired me a lot and in fact most of the concepts
in this module are his ideas ported to perl.

=head1 COPYRIGHT

Copyright (c) 2011-2012 by T.Linden <tlinden@cpan.org>.
All rights reserved.

=head1 LICENSE

This program is free software; you can redistribute it
and/or modify it under the same terms as Perl itself.

=head1 VERSION

Crypt::PWSafe3 Version 1.08.

=cut




1;

