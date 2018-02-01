package com.helger.asic;

public enum EMessageDigestAlgorithm
{
  SHA256 ("SHA-256", "http://www.w3.org/2001/04/xmlenc#sha256"),
  SHA384 ("SHA-384", "http://www.w3.org/2001/04/xmlenc#sha384"),
  SHA512 ("SHA-512", "http://www.w3.org/2001/04/xmlenc#sha512");

  private final String m_sAlgorithm;
  private final String m_sURI;

  private EMessageDigestAlgorithm (final String algorithm, final String uri)
  {
    m_sAlgorithm = algorithm;
    m_sURI = uri;
  }

  public String getAlgorithm ()
  {
    return m_sAlgorithm;
  }

  public String getUri ()
  {
    return m_sURI;
  }
}
