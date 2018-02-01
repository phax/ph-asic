package com.helger.asic;

public class MimeType
{

  public static final MimeType XML = MimeType.forString ("application/xml");

  public static MimeType forString (String mimeType)
  {
    return new MimeType (mimeType);
  }

  private String m_sMimeType;

  private MimeType (String mimeType)
  {
    this.m_sMimeType = mimeType;
  }

  @Override
  public String toString ()
  {
    return m_sMimeType;
  }
}
