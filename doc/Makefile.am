man_MANS = memcached.1

EXTRA_DIST = *.txt

BUILT_SOURCES=

if BUILD_SPECIFICATIONS
BUILT_SOURCES += protocol-binary.txt protocol-binary-range.txt
MOSTLYCLEANFILES = protocol-binary.txt protocol-binary-range.txt
endif

protocol-binary.txt: protocol-binary.full
	@XML2RFC@ -c @abs_builddir@ protocol-binary.full $@

protocol-binary-range.txt: protocol-binary-range.full
	@XML2RFC@ -c @abs_builddir@ protocol-binary-range.full $@

protocol-binary.full: protocol-binary.xml xml2rfc/rfc2629-noinc.xsl
	@XSLTPROC@ --nonet xml2rfc/rfc2629-noinc.xsl protocol-binary.xml > $@

protocol-binary-range.full: protocol-binary-range.xml xml2rfc/rfc2629-noinc.xsl
	@XSLTPROC@ --nonet xml2rfc/rfc2629-noinc.xsl protocol-binary-range.xml > $@

