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
import javax.xml.crypto.dsig.DigestMethod;

import com.helger.commons.annotation.Nonempty;

public enum EMessageDigestAlgorithm
{
  SHA1 ("SHA-1", "SHA1", DigestMethod.SHA1),
  SHA224 ("SHA-224", "SHA224", "http://www.w3.org/2001/04/xmldsig-more#sha224"),
  SHA256 ("SHA-256", "SHA256", DigestMethod.SHA256),
  SHA384 ("SHA-384", "SHA384", "http://www.w3.org/2001/04/xmldsig-more#sha384"),
  SHA512 ("SHA-512", "SHA512", DigestMethod.SHA512);

  public static final EMessageDigestAlgorithm DEFAULT = SHA256;

  private final String m_sMessageDigestAlgorithm;
  private final String m_sContentSignerAlgorithm;
  private final String m_sURI;

  private EMessageDigestAlgorithm (@Nonnull @Nonempty final String sMessageDigestAlgorithm,
                                   @Nonnull @Nonempty final String sContentSignerAlgorithm,
                                   @Nonnull @Nonempty final String sURI)
  {
    m_sMessageDigestAlgorithm = sMessageDigestAlgorithm;
    m_sContentSignerAlgorithm = sContentSignerAlgorithm;
    m_sURI = sURI;
  }

  /**
   * Note: was called "getAlgorithm" prior to v1.4.0
   * 
   * @return The name of the algorithm to be used for <code>MessageDigest</code>
   *         instances. Never <code>null</code> nor empty.
   */
  @Nonnull
  @Nonempty
  public String getMessageDigestAlgorithm ()
  {
    return m_sMessageDigestAlgorithm;
  }

  /**
   * @return The name of the algorithm to be used for JCA content signer
   *         instances. Never <code>null</code> nor empty.
   * @since 1.4.0
   */
  @Nonnull
  @Nonempty
  public String getContentSignerAlgorithm ()
  {
    return m_sContentSignerAlgorithm;
  }

  @Nonnull
  @Nonempty
  public String getUri ()
  {
    return m_sURI;
  }
}
