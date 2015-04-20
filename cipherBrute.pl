#!/usr/bin/perl

#Author: craigmillgate

###########################################

use strict;
use warnings;
use Socket;
use Data::Dumper;
use Getopt::Long;
#use Getopt::Long::Complete
use Crypt::X509;
use Term::ANSIColor;
use File::Basename;
#use List::MoreUtils qw(uniq);
use NetAddr::IP;
use Net::IP;
use Term::ANSIColor;

my $usage = "\nUsage: " . "perl " . basename($0) . " [options]

'options' is one of more of

        --help        Displays this usage message
	--version     Displays current version of this program
	--file	      Specify a file containing list of ips/hostnames 

        EXAMPLE COMMANDS:

	perl cipherBrute.pl -f listofipaddresses.txt

\n";

###########################################

my $version = "\n" . basename($0) . ": Version 0.01 \n\n";

my $file;

GetOptions(
'file=s'	=> \$file,
'help'          => sub { print $usage; exit 0 },
'version'       => sub { print $version; exit 0 },
);

die "\nIncorrect usage - Specify at least a file containing virtualhosts for the most basic functionality (see --help)\n\n" 
unless (defined $file);

###########################################

print color 'green';
my $heredoc = <<'END';

       _       _               ____             _       
      (_)     | |             |  _ \           | |      
   ___ _ _ __ | |__   ___ _ __| |_) |_ __ _   _| |_ ___ 
  / __| | '_ \| '_ \ / _ \ '__|  _ <| '__| | | | __/ _ \
 | (__| | |_) | | | |  __/ |  | |_) | |  | |_| | ||  __/
  \___|_| .__/|_| |_|\___|_|  |____/|_|   \__,_|\__\___|
        | |                                             
        |_|                                                      			 
			 bugs/features to craigmillgate.
									    
END
print "$heredoc"; 
print color 'reset';

###########################################
#menu

my $choice;

while (1)
{
        anon_mainmenu();
}

sub anon_mainmenu {
print color 'green';
print "________________________________________________________\n\n";
print "Bruteforce supported ciphers ....................... [1]\n";
print "SSL Certificate information ........................ [2]\n";
print "[exit] .......................................... [EXIT]\n";
print "\n[>] Enter option: ";
print color 'reset';

chomp($choice = <STDIN>);

if ($choice eq 1) {
	cipher_check(); 
} elsif ($choice eq 2) {
	cert_info();   
} elsif ($choice eq "exit") {
	print "\nExiting...\n\n";
	exit(0);
}

print "\n\n";

}     #end of main menu

###########################################
#getting screenshots

sub cipher_check {

print "________________________________________________________\n\n\n";


my %hashofarrays;  #to store the relationship between hostnames and ips
my @hosts;

open(my $fh, "<", $file) 
	or die "Failed to open file: $!\n";

while(<$fh>) { 
	chomp;
	next if /^(\s)*$/; 
	push @hosts, $_;
}

close $fh;

my %hash = map { $_, 1 } @hosts;   #remove duplicates from the array using a hash
#print Dumper (\%hash);       #for testing only
@hosts = keys %hash;      #reassigning non duplicates

$| = 1; #suffering from buffering prevention

open STDERR, '>/dev/null';    

my @cipher = split(/:/,`openssl ciphers ALL:eNULL`);
#`openssl ciphers 'ALL:eNULL' | sed -e 's/:/ /g'`;

my @protocol_versions = ("-ssl3", "-tls1", "-tls1_1", "-tls1_2");

my $opensslversion = `openssl version`;

colour3("[+]");
print (" Obtaining cipher list from $opensslversion\n");

my $out;
my $v;

foreach my $hosts (@hosts) {

my $substr = ":";
my $derbinary;

if (index($hosts, $substr) != -1) {

	#do 0

} else {

        my $pnumberr = 443;
        $hosts = "$hosts:$pnumberr";

}

colour3("[+]");
colour(" $hosts\n");

    	foreach my $version (@protocol_versions) {
	
		$v = $version;	
		$v =~ tr/-//d;
		colour("\n\t$v\n");

		foreach my $cipher (@cipher) {

			my $out = `echo -n | openssl s_client $version -cipher $cipher -connect $hosts 2>/dev/null`;
			#print "$out\n";
			if (index($out, '-----BEGIN CERTIFICATE-----') != -1) {
    				print "\t$cipher\n";
				#print "\t$cipher - $version SUPPORTED\n";	
			}	
		
			#print "$cipher\n";
		}
	
	#print "\n";		

	}

	print "\n";	
}

exit();

} #end 


###########################################
#getting certificate information

sub cert_info {

print "________________________________________________________\n\n\n";


my @virthostips;

open(my $fh, "<", $file) 
	or die "Failed to open file: $!\n";

while(<$fh>) { 
	chomp;
	push @virthostips, $_;
}
close $fh;

foreach my $vi ( @virthostips ) {

my $substr = ":";
my $derbinary;

if (index($vi, $substr) != -1) {
	
	my ($viip, $pnumb) = split(":",$vi);
	$derbinary = `echo -n | openssl s_client -connect $viip:$pnumb 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -outform DER 2>/dev/null`;
	
	$vi = $viip; #so we can compare the subject cn with the vi (ie ip/virthost supplied)

} else {

	my $pnumber = 443;
	$derbinary = `echo -n | openssl s_client -connect $vi:$pnumber 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -outform DER 2>/dev/null`;

}

###########################################

my $decoded= Crypt::X509->new(cert => $derbinary);
#print Dumper($decoded);    #for testing only


colour3("[+]");
print " Certificate Information for";

if (index($vi, $substr) != -1) {

        my ($viip, $pnumb) = split(":",$vi);
	colour(" $viip:$pnumb\n");

} else {

        my $pnumber = 443;
	colour(" $vi:$pnumber\n");

}

if ($decoded->error) {

	colour2("\t[-] Error Parsing Certificate - No certificate found for [$vi]\n\n\n\n"); #.$decoded->error;
	next;

}

print "\n";

###########################################

my $cn = ($decoded->subject_cn);
my $wildcard = "*";
unless (index($cn, $wildcard) == -1) {

        colour2("\t[-] Wildcard Certificate in use - [$cn]\n");

} #elsif ($vi ne $cn) {

        #colour2("[-] Untrusted Certificate? - CN [$cn] does not match Host [$vi]\n");

#}

###########################################

my $expiry = gmtime($decoded->not_after);
if ($decoded->not_after < time()) {

        colour("\t[-] Expired Certificate - Expired $expiry\n");

}
 
###########################################

print "\tSubject: ";
colour(join(',',@{$decoded->Subject}));
print "\n";

###########################################

print "\tSubject CN: ";
colour($decoded->subject_cn);
print "\n";

###########################################

print "\tSubject Org: ";
colour($decoded->subject_org);
print "\n";

###########################################

print "\tLocation: ";
my $country = ($decoded->subject_country);
my $locality = ($decoded->subject_locality);
my $state = ($decoded->subject_state);
my $address = "$country, $locality, $state";
colour($address);
print "\n";

###########################################

print "\t |\n";

##########################################

print "\tIssuer CN: ";
colour($decoded->issuer_cn);
print "\n";

###########################################

print "\tValid from: ";
my $begins = gmtime($decoded->not_before);
colour($begins);
colour(" GMT\n");
#print colour(" " . gmtime($decoded->not_before) . " GMT\n");

###########################################

print "\tExpires on: ";
my $expiration = gmtime($decoded->not_after);
colour($expiration);
colour(" GMT\n");
#print colour(" " . gmtime($decoded->not_after) . " GMT\n");

###########################################

print "\t |\n";

##########################################

print "\tCertificate Serial Number: ";
print "COMING VERY SOON";
#colour($decoded->serial);
print "\n";

###########################################

print "\tSignature Algorithn: ";
print "COMING VERY SOON";
#colour($decoded->SigEncAlg);
print "\n";

###########################################

print "\tSignature Hash: ";
print "COMING VERY SOON";
#colour($decoded->SigHashAlg);
print "\n";

###########################################

print "\n\n\n";

} #foreach

exit();

} #end of subroutine call

###########################################
#end

sub colour {

print color 'yellow';
print "$_[0]";  #should never recieve more arguments so subroutine array call unnecessary
print color 'reset';

}

sub colour2 {

print color 'red';
print "$_[0]";  #should never recieve more arguments so subroutine array call unnecessary
print color 'reset';

}

sub colour3 {

print color 'green';
print "$_[0]";  #should never recieve more arguments so subroutine array call unnecessary
print color 'reset';

}

sub colour4 {

print color 'bold red';
print "$_[0]";  #should never recieve more arguments so subroutine array call unnecessary
print color 'reset';

}

###########################################
#end

