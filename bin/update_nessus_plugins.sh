#!/bin/sh

cd /tmp
/usr/local/sbin/nessus-update-plugins
# after the plugins are updated, nessus thinks for a bit
# before you can connect to it. 
sleep 300
/opt/netpass/bin/import_nessus_scans.pl
exit 0
