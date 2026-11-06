# Generated from Makefile.PL using makefilepl2cpanfile

requires 'perl', '5.014';

requires 'Carp';
requires 'Cwd';
requires 'Data::Validate::IP', '0.31';
requires 'Digest::MD5';
requires 'Encode';
requires 'Errno';
requires 'Fcntl';
requires 'Getopt::Long', '2.50';
requires 'HTML::Parser', '3.71';
requires 'HTML::SimpleLinkExtor', '1.20';
requires 'IPC::System::Simple', '1.30';
requires 'IO::Select', '1.17';
requires 'IO::Socket::INET', '1.31';
requires 'IO::Socket::SSL', '2.000';
requires 'JSON::PP', '4.00';
requires 'Net::SSLeay', '1.92';
requires 'Params::Get', '0.17';
requires 'Params::Validate::Strict', '0.41';
requires 'POSIX';
requires 'Readonly', '2.05';
requires 'Scalar::Util';
requires 'Socket', '2.020';
requires 'Sub::Private', '0.09';
requires 'Sub::Protected', '0.03';
requires 'Term::ANSIColor';
requires 'Time::HiRes', '1.97';
requires 'Time::Local', '1.28';
requires 'URI', '1.70';
requires 'autodie', '2.37';
requires 'parent';
requires 'version';

on 'test' => sub {
	requires 'File::Temp';
	requires 'Test::Fatal';
	requires 'Test::More', '1.302';
};

on 'develop' => sub {
	requires 'Devel::Cover';
	requires 'Perl::Critic';
	requires 'Test::Pod';
	requires 'Test::Pod::Coverage';
};
