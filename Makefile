dist:
	(NPVERSION=`head -1 VERSION` ; \
	 NPBASEN=`basename $${PWD}` ; \
	 cd .. ; \
	 echo $${NPVERSION} $${NPBASEN} ; \
	 mv $${NPBASEN} NetPass-$${NPVERSION} ;      \
	 tar -cp --exclude CVS -f NetPass-$${NPVERSION}.tar NetPass-$${NPVERSION} ; \
	 gzip -v -9 NetPass-$${NPVERSION}.tar ; \
	 mv NetPass-$${NPVERSION} $${NPBASEN} )

clean:
	find . -name \*~ -exec rm -f {} \;
	find . -name \*.old -exec rm -f {} \;
	find . -name .#\* -exec rm -f {} \;

manifest: clean
	find . -type f -print | egrep -v '(CVS|.nfs|.#)' | \
		sed -e 's/\.\///' > MANIFEST

.PHONY: install

# e.g.
# sudo make install EXCLUDE="--exclude='BeginScan' --exclude='.*\.mhtml'"

install:
	./install -c $(EXCLUDE) /opt/netpass
	/etc/init.d/apache stop
	sleep 5
	/etc/init.d/apache start

