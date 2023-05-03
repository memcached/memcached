man_MANS = memcached.1

SPECIFICATIONS = protocol-binary.txt protocol-binary-range.txt

EXTRA_DIST = $(srcdir)/*.txt

# When we make dist always include the generated specifications so people don't
# have to have xml2rfc and xsltproc installed
EXTRA_DIST += $(SPECIFICATIONS)

BUILT_SOURCES =
MOSTLYCLEANFILES =
#if BUILD_SPECIFICATIONS
#BUILT_SOURCES    += $(SPECIFICATIONS)
#MOSTLYCLEANFILES += $(SPECIFICATIONS)
#endif

#RFC2629_XSL = $(srcdir)/xml2rfc/rfc2629-noinc.xsl
#RFC2629_DTD = $(srcdir)/xml2rfc/rfc2629.dtd

#%.txt: %.full $(RFC2629_DTD)
#	@XML2RFC@ -d $(RFC2629_DTD) -c $(builddir) $< $@
#
#%.full: %.xml $(RFC2629_XSL)
#	@XSLTPROC@ --nonet $(RFC2629_XSL) $< > $@

# Prevent make from deleting intermediate files
#all-full: $(SPECIFICATIONS:.txt=.full)

#clean-local:
#	rm -f $(SPECIFICATIONS:.txt=.full)

#.PHONY: all-full
