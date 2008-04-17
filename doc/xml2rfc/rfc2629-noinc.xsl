<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                version="1.0">

  <xsl:output method="xml"/>

  <xsl:template name='noinc'>
    <xsl:apply-templates mode='noinc'/>
  </xsl:template>

  <xsl:template match="*" mode='noinc'>
    <xsl:copy>
      <xsl:apply-templates select='@*' mode='noinc'/>
      <xsl:apply-templates mode='noinc'/>
    </xsl:copy>
  </xsl:template>
  <xsl:template match='@*' mode='noinc'>
    <xsl:attribute name='{name()}'>
      <xsl:value-of select='.'/>
    </xsl:attribute>
  </xsl:template>

  <xsl:template match='processing-instruction("rfc")' mode='noinc'>
    <xsl:choose>
      <xsl:when test='substring-before(.,"=") = "include"'>
        <xsl:call-template name='include-pi'>
          <xsl:with-param name='include-href'>
            <xsl:value-of select="translate( substring-after( ., '=' ), '&quot; ', '' )"/><xsl:text>.xml</xsl:text>
          </xsl:with-param>
        </xsl:call-template>
      </xsl:when>
      <xsl:otherwise>
        <xsl:copy-of select='.'/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name='include-pi'>
    <xsl:param name='include-href'/>
    <xsl:apply-templates select="document( $include-href )" mode='noinc'/>
  </xsl:template>

  <xsl:template match='dwdrfc-ref' mode='noinc'>
	<xsl:param name='include-href'>
          <xsl:choose>
            <xsl:when test='starts-with( @src, "http://" )'>
              <xsl:value-of select='@src'/>
            </xsl:when>
            <xsl:otherwise>
              <xsl:text>http://xml.resource.org/public/rfc/</xsl:text>
              <xsl:value-of select='@src'/>
              <xsl:text>.xml</xsl:text>
            </xsl:otherwise>
          </xsl:choose>
	</xsl:param>
        <reference anchor="{@anchor}">
          <xsl:apply-templates select="document( $include-href )" mode="refrename"/>
	</reference>
  </xsl:template>

	<xsl:template match='*' mode='refrename'>
	<xsl:apply-templates mode='refrename'/>
	</xsl:template>

	<xsl:template match='reference' mode='refrename'>
	<xsl:apply-templates mode='noinc'/>
	</xsl:template>

  <xsl:template match='/'>
    <xsl:call-template name='noinc'/>
  </xsl:template>

  <xsl:template name='output'>
    <xsl:param name='foo'/>
    <xsl:copy-of select='$foo'/>
    <xsl:apply-templates select='$foo'/>
  </xsl:template>

  <xsl:template match='*' mode='output'>
    <element>
      <xsl:value-of select='name()'/>
      <xsl:apply-templates mode='output'/>
    </element>
  </xsl:template>
  <xsl:template match='text()' mode='output'/>

  <!-- Reference checking attributes stripped here. -->
  <xsl:template match='references' mode='noinc'>
    <xsl:element name='references'>
      <xsl:attribute name='title'>
        <xsl:value-of select='@title'/>
      </xsl:attribute>
      <xsl:apply-templates mode='noinc'/>
    </xsl:element>
  </xsl:template>

  <xsl:template match='xref' mode='noinc'>
    <xsl:element name='xref'>
      <xsl:attribute name='target'>
        <xsl:value-of select='@target'/>
      </xsl:attribute>
      <xsl:apply-templates mode='noinc'/>
    </xsl:element>
  </xsl:template>

</xsl:stylesheet>
