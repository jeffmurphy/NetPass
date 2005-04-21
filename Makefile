dist:
	(cd .. ; tar -cp --exclude CVS -f netpass-`cat NetPass/VERSION`.tar NetPass)

clean:
	find . -name \*~ -exec rm -f {} \;
	find . -name \*.old -exec rm -f {} \;
	find . -name .#\* -exec rm -f {} \;

manifest: clean
	find . -type f -print | egrep -v '(CVS|.nfs|.#)' | \
		sed -e 's/\.\///' > MANIFEST

