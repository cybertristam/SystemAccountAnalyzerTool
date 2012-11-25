#!/bin/perl

=head1 TITLE

 systemAccountAnalyzer.pl

=head1 SYNOPSIS

perl_example.pl [ -h|-v ]

=head1 DESCRIPTION

 This Perl code reads in a shadow file and alerts on any user whos password is going to expire inside of the warning period.

=head1 ARGUMENTS

 Place
 --help        print Options and Arguments
 --version     print version information

=head1 OPTIONS


=head1 LICENSE



=head1 AUTHOR

Copyright (C) Jon Wright 2010
All rights reserved

=cut

use strict 'vars';
use warnings;
use Getopt::Std;
use Pod::Usage;
use Sys::Syslog;
use Fcntl;
use Switch;
use Time::Local;

use constant VERSION => '1.0.0';
use constant LOGTYPE => '3';
use constant DEFSHADOWFILE => '/etc/shadow';
use constant LOGABR => 'pep';
use constant LVLREGEX => qr/emerg|alert|crit|err|warning|notice|info|debug/;
use constant MSGREGEX => qr/([-\@\w.]+)$/;
use constant DEFSYSLVL => 'err';
use constant DEFSYSFLY => 'local7';

use constant EXPDATE => '60';
use constant WARNDATE => '14';
use constant DELDATE => '90';

use constant SECSINDAY => '86400';

sub logit{
	my ($level, $message) = @_;
	if ($level =~ LVLREGEX) {
		if ($message =~ MSGREGEX ) {
			switch (LOGTYPE) {
				case  0 {
					&printMsg(STDOUT,$level,$message);
				}
				case 1 {
					&printMsg(STDOUT,$level,$message);
				}
				case 2 {
					&syslogMsg($level,$message);
				}
				case 3 {
					&printMsg(STDOUT,$level,$message);
					&syslogMsg($level,$message);
				}
				case 4 {
					&printMsg(STDERR,$level,$message);
					&syslogMsg($level,$message);
				}
			}
		}
		else {
			&printMsg(STDERR,DEFSYSLVL,"The Message contains values that are non-alphanumeric or non-valid special characters".$message);
		}
	}
	else {
		&printMsg(STDERR,DEFSYSLVL,"The Level Argument contains values to are not a valid Message Level");
	}
	return 1;
}

sub printMsg {
	my $fileHandler = shift;
	my ($prLvl, $prMsg) = @_;
	if ($prLvl =~ LVLREGEX) {
		if ($prMsg =~ MSGREGEX) {
			printf($fileHandler "%s [%s] %s\n",LOGABR, $prLvl,$prMsg);
		}
		else {
			printf(STDERR "%s [%s] %s\n",LOGABR, DEFSYSLVL,"The Message contains values that are non-alphanumeric or non-valid special characters");
		}
	}
	else {
		printf(STDERR "%s [%s] %s\n",LOGABR, DEFSYSLVL,"The Level Argument contains values to are not a valid Message Level");
	}
	return 1;
}

sub syslogMsg{
	my ($sysLvl, $sysMsg) = @_;
	if ($sysLvl =~ LVLREGEX) {
		if ($sysMsg =~ MSGREGEX) {
			openlog(LOGABBR, 'cons,pid', 'user');
			syslog(DEFSYSFLY.".".$sysLvl, $sysMsg);
			closelog();
		}
		else {
			$sysMsg = "The Message contains values that are non-alphanumeric or non-valid special characters";
			&printMsg(STDERR,DEFSYSLVL,$sysMsg);
			openlog(LOGABBR, 'cons,pid', 'user');
			syslog(DEFSYSFLY.".".DEFSYSLVL, $sysMsg);
			closelog();
		}
	}
	else {
		$sysMsg = "The Level Argument contains values to are not a valid Message Level";
		&printMsg(STDERR,DEFSYSLVL,$sysMsg);
		openlog(LOGABBR, 'cons,pid', 'user');
		syslog(DEFSYSFLY.".".DEFSYSLVL, $sysMsg);
		closelog();
	}
	return 1;
}
sub alertMsg{
	my ($altUsr, $altLvl, $altMsg) = @_;
	if ($altLvl =~ LVLREGEX) {
		if ($altMsg =~ MSGREGEX) {
			logit($altLvl,$altMsg." : ".$altUsr);
		}
		else {
			&logit(DEFSYSLVL,"The Message contains values that are non-alphanumeric or non-valid special characters");
		}
	}
	else {
		&logit(DEFSYSLVL,"The Level Argument contains values to are not a valid Message Level");
	}
	return 1;
}

sub main::HELP_MESSAGE{
    &pod2usage();
	return 1;
}

sub main::VERSION_MESSAGE{
    printf(STDERR "Version: %s",VERSION);
	return 1;
}

sub determineAlert {
	my ($name,$lastSetDate,$expDate,$warnDate) = @_;
	my $currentTime = timegm(gmtime());
	my $dateValue;
	if((!defined($expDate)) || ($expDate !~ m/^\d+$/)){
		$expDate=EXPDATE;
	}
	if((!defined($warnDate)) || ($warnDate !~ m/^\d+$/)){
		$warnDate=WARNDATE;
	}
	if((!defined($expDate)) || ($lastSetDate !~ m/^\d+$/)){
		$lastSetDate=0;
		&alertMsg($name,"alert","This user account has never logged in");
	}
	$dateValue = (($currentTime - ($lastSetDate + (($expDate * SECSINDAY) - ($warnDate * SECSINDAY))))/SECSINDAY);
	if (($dateValue >= ($warnDate * -1) && ($dateValue <=1))) {
		&alertMsg($name,"info","This user account expires in ".$dateValue." days.");
	}
	elsif (($dateValue > -1) && ($dateValue <= 0)){
		&alertMsg($name,"notice","This user account expires today.");
	}
	elsif(($dateValue > 0) && ($dateValue < DELDATE)){
		&alertMsg($name,"warning","This user account expired today.");
	}
	elsif($dateValue > DELDATE){
		&alertMsg($name,"alert", "This user account should be deleted");
	}
	return 1;
}

sub alertOnExpiringAccounts {
	my ($filename) = @_;
	my @shadowLineArray = ();
	my $line;
	if (-e $filename) {
		if(sysopen(FH,$filename,O_RDONLY)){
			while($line = <FH>){
				@shadowLineArray = split(/:/, $line);
				chomp(@shadowLineArray);
				if (($shadowLineArray[1] !~ /^NP$/) && ($shadowLineArray[0] !~ /^root$/)){
					determineAlert($shadowLineArray[0],$shadowLineArray[2],$shadowLineArray[4],$shadowLineArray[5]);
				}
			}
		}
		close(FH);
	}
	else {
		logit(INFO,"Unable to locate 'SHADOW File: ".$filename);
	}
}


sub main {
    my %options;
    &getopts('hvf:', \%options); # options as above. Values in %opts
    if (defined $options{h}){
        &main::HELP_MESSAGE;
    }
    elsif (defined $options{v}){
        &main::VERSION_MESSAGE;
    }
	elsif (defined $options{f}){
		&alertOnExpiringAccounts($options{f});
	}
	else {
		&alertOnExpiringAccounts(DEFSHADOWFILE);
	}
	
}

&main;