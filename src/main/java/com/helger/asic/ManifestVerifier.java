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

import com.helger.asic.jaxb.asic.AsicFile;
import com.helger.asic.jaxb.asic.AsicManifest;
import com.helger.asic.jaxb.asic.Certificate;

public class ManifestVerifier
{
  private final EMessageDigestAlgorithm m_eMD;

  private final AsicManifest m_aAsicManifest = new AsicManifest ();
  private final Map <String, AsicFile> m_aAsicManifestMap = new HashMap <> ();

  public ManifestVerifier (final EMessageDigestAlgorithm messageDigestAlgorithm)
  {
    m_eMD = messageDigestAlgorithm;
  }

  public void update (final String filename, final byte [] digest, final String sigReference)
  {
    update (filename, null, digest, null, sigReference);
  }

  public void update (final String filename,
                      final String mimetype,
                      final byte [] digest,
                      final String digestAlgorithm,
                      final String sigReference)
  {
    if (m_eMD != null && digestAlgorithm != null && !digestAlgorithm.equals (m_eMD.getUri ()))
      throw new IllegalStateException (String.format ("Wrong digest method for file %s: %s",
                                                      filename,
                                                      digestAlgorithm));

    AsicFile asicFile = m_aAsicManifestMap.get (filename);

    if (asicFile == null)
    {
      asicFile = new AsicFile ();
      asicFile.setName (filename);
      asicFile.setDigest (digest);
      asicFile.setVerified (false);

      m_aAsicManifest.getFile ().add (asicFile);
      m_aAsicManifestMap.put (filename, asicFile);
    }
    else
    {
      if (!Arrays.equals (asicFile.getDigest (), digest))
        throw new IllegalStateException (String.format ("Mismatching digest for file %s", filename));

      asicFile.setVerified (true);
    }

    if (mimetype != null)
      asicFile.setMimetype (mimetype);
    if (sigReference != null)
      asicFile.getCertRef ().add (sigReference);

  }

  public void addCertificate (final Certificate certificate)
  {
    this.m_aAsicManifest.getCertificate ().add (certificate);
  }

  public void setRootFilename (final String filename)
  {
    m_aAsicManifest.setRootfile (filename);
  }

  public void verifyAllVerified ()
  {
    for (final AsicFile asicFile : m_aAsicManifest.getFile ())
      if (!asicFile.isVerified ())
        throw new IllegalStateException (String.format ("File not verified: %s", asicFile.getName ()));
  }

  public AsicManifest getAsicManifest ()
  {
    return m_aAsicManifest;
  }
}
