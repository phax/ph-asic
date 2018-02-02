/**
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018 Philip Helger (www.helger.com)
 * philip[at]helger[dot]com
 *
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed
 * with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/
 */
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
