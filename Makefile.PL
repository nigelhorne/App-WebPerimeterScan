use ExtUtils::MakeMaker;

my $dist = {
	COMPRESS => 'gzip -9f',	# Compress tarball using gzip
	SUFFIX => 'gz',	# File suffix for tarball
};

if($^O eq 'darwin') {
	$dist->{'TAR'} = 'gtar';
}

WriteMakefile(
	NAME          => 'App::WebPerimeterScan',
	VERSION_FROM  => 'lib/App/WebPerimeterScan.pm',
	MIN_PERL_VERSION => '5.010',
	LICENSE       => 'gpl_2',
	EXE_FILES     => ['bin/webperimeter'],
	PREREQ_PM     => {
		'Digest::MD5'            => 0,
		'Errno'                  => 0,
		'Fcntl'                  => 0,
		'Getopt::Long'           => 2.50,
		'HTML::SimpleLinkExtor'  => 1.20,
		'IO::Select'             => 1.17,
		'IO::Socket::INET'       => 1.31,
		'IO::Socket::SSL'        => 2.000,
		'JSON::PP'               => 4.00,
		'Net::SSLeay'            => 1.92,
		'POSIX'                  => 0,
		'Socket'                 => 2.020,
		'Term::ANSIColor'        => 0,
		'Test::More'             => 1.302,
		'Time::HiRes'            => 1.97,
		'Time::Local'            => 1.28,
		'URI'                    => 1.70,
		'version' => 0,
	}, TEST_REQUIRES => {
		'Test::Fatal' => 0,
	},
	ABSTRACT      => 'Check the parts of your own web perimeter that an outsider can reach',
	AUTHOR        => 'Nigel Horne <njh@nigelhorne.com>',
	dist => $dist,
	clean	=> { FILES => 'App-WebPermieterScan-*' },
);
