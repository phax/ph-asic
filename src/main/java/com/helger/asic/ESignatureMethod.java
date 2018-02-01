package com.helger.asic;

public enum ESignatureMethod
{
  CAdES (EMessageDigestAlgorithm.SHA256),
  XAdES (EMessageDigestAlgorithm.SHA256);

  private EMessageDigestAlgorithm m_eMD;

  ESignatureMethod (final EMessageDigestAlgorithm messageDigestAlgorithm)
  {
    this.m_eMD = messageDigestAlgorithm;
  }

  public EMessageDigestAlgorithm getMessageDigestAlgorithm ()
  {
    return m_eMD;
  }
}
