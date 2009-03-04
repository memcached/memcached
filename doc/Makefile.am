man_MANS = memcached.1

EXTRA_DIST = *.txt

BUILT_SOURCES=

if BUILD_SPECIFICATIONS
BUILT_SOURCES += protocol-binary.txt protocol-binary-range.txt
MOSTLYCLEANFILES = protocol-binary.txt protocol-binary-range.txt
endif

%.txt: %.full
	@XML2RFC@ $< $@

%.chk: %.xml xml2rfc/rfc2629-refchk.xsl
	@XSLTPROC@ xml2rfc/rfc2629-refchk.xsl $< >$@

%.full: %.xml xml2rfc/rfc2629-noinc.xsl
	@XSLTPROC@ xml2rfc/rfc2629-noinc.xsl $< >$@

