<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                version="1.0">

  <xsl:output method="xml"/>

  <xsl:template match='/'>
    <refcheck>
      <xsl:apply-templates select='//xref' mode='missing'/>
      <xsl:apply-templates select='//reference' mode='orphans'/>
      <xsl:apply-templates select='//references[@dwdrfc-type = "norm"]' mode='normcheck'/>
      <xsl:apply-templates select='//xref[@dwdrfc-type = "norm"]' mode='normrefs'/>
    </refcheck>
  </xsl:template>

  <xsl:template match='xref' mode='missing'>
    <xsl:param name='refname'>
      <xsl:value-of select='@target'/>
    </xsl:param>
    <xsl:param name='reftgt'>
      <xsl:value-of select='//*[@anchor = $refname]/@anchor'/>
    </xsl:param>
    <xsl:choose>
      <xsl:when test='$reftgt = $refname'/>
      <xsl:otherwise>
        <missing><xsl:value-of select='$refname'/></missing><xsl:text>
      </xsl:text>
    </xsl:otherwise>
  </xsl:choose>
  </xsl:template>

  <xsl:template match='xref' mode='normrefs'>
    <xsl:param name='refname'>
      <xsl:value-of select='@target'/>
    </xsl:param>
    <xsl:param name='reftgt'>
      <xsl:value-of select='//references[@dwdrfc-type = "norm"]/*[@anchor = $refname]/@anchor'/>
    </xsl:param>
    <xsl:choose>
      <xsl:when test='$reftgt = $refname'/>
      <xsl:otherwise>
        <missing-norm><xsl:value-of select='$refname'/></missing-norm><xsl:text>
      </xsl:text>
    </xsl:otherwise>
  </xsl:choose>
  </xsl:template>

  <xsl:template match='reference' mode='orphans'>
    <xsl:param name='refname'>
      <xsl:value-of select='@anchor'/>
    </xsl:param>
    <xsl:param name='reftgt'>
      <xsl:value-of select='//xref[@target = $refname]/@target'/>
    </xsl:param>
    <xsl:if test='$reftgt != $refname'>
      <orphan><xsl:value-of select='$refname'/></orphan><xsl:text>
    </xsl:text>
  </xsl:if>
</xsl:template>

<xsl:template match='references' mode='normcheck'>
  <xsl:apply-templates mode='normcheck'/>
</xsl:template>

<xsl:template match='*' mode='normcheck'>
  <!-- Need to find at least one normative reference -->
  <xsl:param name='refname'>
    <xsl:value-of select='@anchor'/>
  </xsl:param>
  <xsl:param name='reftgt'>
    <xsl:value-of select='//xref[@dwdrfc-type = "norm" and @target = $refname]/@target'/>
  </xsl:param>
  <xsl:if test='$refname != $reftgt'>
    <normchk><xsl:value-of select='$refname'/></normchk><xsl:text>
</xsl:text>
  </xsl:if>
</xsl:template>

<xsl:template match='text()' mode='normcheck'/>

</xsl:stylesheet>
