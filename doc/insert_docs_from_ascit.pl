#!/usr/bin/perl

use strict;
use DBI;

my $filename = shift;

open (FH, $filename);

my $f = 0;
my $msg = "";
while (my $line = <FH>) {

	$f = 1 if ($line =~ /<body>/i); 
	last if ($line =~ /<\/body>/i);

	if ($f && $line !~ /<body>/i) {
		$line =~ s/<!--[^>]*-->//g;
		$msg .= $line;
	}
}

close (FH);

$filename =~ s/\.htm//;

my $cstr = "DBI:mysql:database=netpass;host=localhost";
my $dbh = DBI->connect($cstr, "root", "");
my $insert = "INSERT INTO pages values(\"msg:$filename\", '$msg')";
my $update = "UPDATE nessusScans set info = \"msg:$filename\" WHERE pluginID = \"$filename\" LIMIT 1";

$dbh->do($insert);
$dbh->do($update);
$dbh->disconnect;

exit 0;
