man_MANS = memcached.1

EXTRA_DIST = *.txt

BUILT_SOURCES=

if BUILD_SPECIFICATIONS
BUILT_SOURCES += protocol-binary.txt protocol-binary-range.txt
MOSTLYCLEANFILES = protocol-binary.txt protocol-binary-range.txt
endif

protocol-binary.txt: $(.TARGET:R).full
	@XML2RFC@ -c @abs_builddir@ $(.TARGET:R).full $@

protocol-binary-range.txt: $(.TARGET:R).full
	@XML2RFC@ -c @abs_builddir@ $(.TARGET:R).full $@

protocol-binary.full: $(.TARGET:R).xml xml2rfc/rfc2629-noinc.xsl
	@XSLTPROC@ --nonet xml2rfc/rfc2629-noinc.xsl $(.TARGET:R).xml > $@

protocol-binary-range.full: $(.TARGET:R).xml xml2rfc/rfc2629-noinc.xsl
	@XSLTPROC@ --nonet xml2rfc/rfc2629-noinc.xsl $(.TARGET:R).xml > $@

