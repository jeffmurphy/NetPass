#!/bin/sh

/usr/local/bin/nessus-fetch --plugins
/opt/netpass/bin/import_nessus_scans.pl
exit 0
