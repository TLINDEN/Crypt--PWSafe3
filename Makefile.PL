require 5.004;
use ExtUtils::MakeMaker;

WriteMakefile(
	      'NAME'         => 'Crypt::PWSafe3',
	      'VERSION_FROM' => 'lib/Crypt/PWSafe3.pm',
	      'PREREQ_PM'    => { 'Digest::HMAC'   => 1.00,
				  'Digest::SHA'    => 1.00,
				  'Crypt::CBC'     => 2.30,
				  'Crypt::ECB'     => 1.45,
				  'Crypt::Twofish' => 2.14,
				  'Crypt::Random'  => 1.25,
				  'Data::UUID'     => 1.217,
				  'Shell'          => 0.5,
				},
	      'AUTHOR'       => 'Thomas Linden <tlinden@cpan.org>',
	      'clean'        => {
				 FILES                   => 't/*.out *~ */*~ */*/*~ */*/*/*~'
				},

);

