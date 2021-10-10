/*
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018-2021 Philip Helger (www.helger.com)
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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;

import com.helger.commons.annotation.Nonempty;

public enum EMessageDigestAlgorithm
{
  SHA1 ("SHA-1", "SHA1", OIWObjectIdentifiers.idSHA1, DigestMethod.SHA1),
  SHA224 ("SHA-224", "SHA224", NISTObjectIdentifiers.id_sha224, "http://www.w3.org/2001/04/xmldsig-more#sha224"),
  SHA256 ("SHA-256", "SHA256", NISTObjectIdentifiers.id_sha256, DigestMethod.SHA256),
  SHA384 ("SHA-384", "SHA384", NISTObjectIdentifiers.id_sha384, "http://www.w3.org/2001/04/xmldsig-more#sha384"),
  SHA512 ("SHA-512", "SHA512", NISTObjectIdentifiers.id_sha512, DigestMethod.SHA512);

  public static final EMessageDigestAlgorithm DEFAULT = SHA256;

  private final String m_sMessageDigestAlgorithm;
  private final String m_sContentSignerAlgorithm;
  private final ASN1ObjectIdentifier m_aOID;
  private final String m_sURI;

  private EMessageDigestAlgorithm (@Nonnull @Nonempty final String sMessageDigestAlgorithm,
                                   @Nonnull @Nonempty final String sContentSignerAlgorithm,
                                   @Nonnull final ASN1ObjectIdentifier aOID,
                                   @Nonnull @Nonempty final String sURI)
  {
    m_sMessageDigestAlgorithm = sMessageDigestAlgorithm;
    m_sContentSignerAlgorithm = sContentSignerAlgorithm;
    m_aOID = aOID;
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

  public boolean isSHA1 ()
  {
    return this == SHA1;
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

  /**
   * @return The OID of the algorithm. Never <code>null</code>.
   * @since 1.4.1
   */
  @Nonnull
  public ASN1ObjectIdentifier getOID ()
  {
    return m_aOID;
  }
}
