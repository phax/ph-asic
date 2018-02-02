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

public enum ESignatureMethod
{
  CAdES (EMessageDigestAlgorithm.SHA256),
  XAdES (EMessageDigestAlgorithm.SHA256);

  private EMessageDigestAlgorithm m_eMD;

  private ESignatureMethod (final EMessageDigestAlgorithm messageDigestAlgorithm)
  {
    m_eMD = messageDigestAlgorithm;
  }

  public EMessageDigestAlgorithm getMessageDigestAlgorithm ()
  {
    return m_eMD;
  }
}
