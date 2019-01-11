/**
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018-2019 Philip Helger (www.helger.com)
 * philip[at]helger[dot]com
 *
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed
 * with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/
 */
package com.helger.asic;

import javax.annotation.Nonnull;

import com.helger.commons.annotation.Nonempty;

public enum EMessageDigestAlgorithm
{
  SHA256 ("SHA-256", "http://www.w3.org/2001/04/xmlenc#sha256"),
  SHA384 ("SHA-384", "http://www.w3.org/2001/04/xmlenc#sha384"),
  SHA512 ("SHA-512", "http://www.w3.org/2001/04/xmlenc#sha512");

  private final String m_sAlgorithm;
  private final String m_sURI;

  private EMessageDigestAlgorithm (@Nonnull @Nonempty final String algorithm, @Nonnull @Nonempty final String uri)
  {
    m_sAlgorithm = algorithm;
    m_sURI = uri;
  }

  @Nonnull
  @Nonempty
  public String getAlgorithm ()
  {
    return m_sAlgorithm;
  }

  @Nonnull
  @Nonempty
  public String getUri ()
  {
    return m_sURI;
  }
}
