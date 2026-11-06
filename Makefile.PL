use ExtUtils::MakeMaker;

WriteMakefile(
	NAME          => 'App::WebPerimeterScan',
	VERSION_FROM  => 'lib/App/WebPerimeterScan.pm',
	LICENSE       => 'gpl_2',
	EXE_FILES     => ['bin/webperimeter'],
	PREREQ_PM     => {
		'Digest::MD5'            => 0,
		'Errno'                  => 0,
		'Fcntl'                  => 0,
		'Getopt::Long'           => 2.50,
		'HTML::SimpleLinkExtor'  => 1.20,
		'IO::Select'             => 1.20,
		'IO::Socket::INET'       => 1.35,
		'IO::Socket::SSL'        => 2.000,
		'JSON::PP'               => 4.00,
		'Net::SSLeay'            => 1.46,
		'POSIX'                  => 0,
		'Socket'                 => 2.020,
		'Term::ANSIColor'        => 0,
		'Test::More'             => 1.302,
		'Time::HiRes'            => 1.97,
		'Time::Local'            => 1.28,
		'URI'                    => 1.70,
	}, TEST_REQUIRES => {
		'Test::Fatal' => 0,
	},
	ABSTRACT      => 'Check the parts of your own web perimeter that an outsider can reach',
	AUTHOR        => 'Nigel Horne <njh@nigelhorne.com>',
);
