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

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import com.helger.asic.jaxb.asic.AsicFile;
import com.helger.asic.jaxb.asic.AsicManifest;
import com.helger.asic.jaxb.asic.Certificate;

public class ManifestVerifier
{
  private final EMessageDigestAlgorithm m_eReferenceMD;

  private final AsicManifest m_aAsicManifest = new AsicManifest ();
  private final Map <String, AsicFile> m_aAsicManifestMap = new HashMap <> ();

  public ManifestVerifier (@Nullable final EMessageDigestAlgorithm eReferenceMD)
  {
    m_eReferenceMD = eReferenceMD;
  }

  public void update (@Nonnull final String sFilename,
                      @Nonnull final byte [] aDigest,
                      @Nullable final String sSigReference)
  {
    update (sFilename, null, aDigest, null, sSigReference);
  }

  public void update (@Nonnull final String sFilename,
                      @Nullable final String sMimeType,
                      @Nonnull final byte [] aDigest,
                      @Nullable final String sDigestAlgorithm,
                      @Nullable final String sSigReference)
  {
    if (m_eReferenceMD != null && sDigestAlgorithm != null && !sDigestAlgorithm.equals (m_eReferenceMD.getUri ()))
      throw new IllegalStateException ("Wrong digest method for file " + sFilename + ": " + sDigestAlgorithm);

    AsicFile aAsicFile = m_aAsicManifestMap.get (sFilename);
    if (aAsicFile == null)
    {
      aAsicFile = new AsicFile ();
      aAsicFile.setName (sFilename);
      aAsicFile.setDigest (aDigest);
      aAsicFile.setVerified (false);

      m_aAsicManifest.getFile ().add (aAsicFile);
      m_aAsicManifestMap.put (sFilename, aAsicFile);
    }
    else
    {
      if (!Arrays.equals (aAsicFile.getDigest (), aDigest))
        throw new IllegalStateException ("Mismatching digest for file " + sFilename);

      aAsicFile.setVerified (true);
    }

    if (sMimeType != null)
      aAsicFile.setMimetype (sMimeType);
    if (sSigReference != null)
      aAsicFile.getCertRef ().add (sSigReference);

  }

  public void addCertificate (@Nonnull final Certificate certificate)
  {
    m_aAsicManifest.addCertificate (certificate);
  }

  public void setRootFilename (final String filename)
  {
    m_aAsicManifest.setRootfile (filename);
  }

  public void verifyAllVerified () throws IllegalStateException
  {
    for (final AsicFile asicFile : m_aAsicManifest.getFile ())
      if (!asicFile.isVerified ())
        throw new IllegalStateException ("File not verified: " + asicFile.getName ());
  }

  @Nonnull
  public AsicManifest getAsicManifest ()
  {
    return m_aAsicManifest;
  }
}
