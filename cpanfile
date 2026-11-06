# Generated from Makefile.PL using makefilepl2cpanfile

requires 'Digest::MD5';
requires 'Errno';
requires 'Fcntl';
requires 'Getopt::Long', '2.50';
requires 'HTML::SimpleLinkExtor', '1.20';
requires 'IO::Select', '1.20';
requires 'IO::Socket::INET', '1.35';
requires 'IO::Socket::SSL', '2.000';
requires 'JSON::PP', '4.00';
requires 'Net::SSLeay', '1.46';
requires 'POSIX';
requires 'Socket', '2.020';
requires 'Term::ANSIColor';
requires 'Test::More', '1.302';
requires 'Time::HiRes', '1.97';
requires 'Time::Local', '1.28';
requires 'URI', '1.70';

on 'test' => sub {
	requires 'Test::Fatal';
};

on 'develop' => sub {
	requires 'Devel::Cover';
	requires 'Perl::Critic';
	requires 'Test::Pod';
	requires 'Test::Pod::Coverage';
};
