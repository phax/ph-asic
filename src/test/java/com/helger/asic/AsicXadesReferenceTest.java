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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.IOException;

import org.junit.Ignore;
import org.junit.Test;

import com.helger.commons.io.resource.ClassPathResource;

public final class AsicXadesReferenceTest
{
  private final AsicVerifierFactory m_aAsicVerifierFactory = AsicVerifierFactory.newFactory (EMessageDigestAlgorithm.DEFAULT);

  // Fetched from
  // http://begrep.difi.no/SikkerDigitalPost/1.2.0/eksempler/post.asice.zip
  @Test
  public void validSdp () throws IOException
  {
    try (final AsicVerifier asicVerifier = m_aAsicVerifierFactory.verify (ClassPathResource.getInputStream ("/asic/asic-xades-external-sdp.asice")))
    {
      assertEquals (asicVerifier.getAsicManifest ().getFile ().size (), 6);
    }
  }

  // Fetched from
  // https://github.com/open-eid/digidoc4j/blob/master/testFiles/test.asice
  @Test
  public void validDigidoc4j () throws IOException
  {
    try (final AsicVerifier asicVerifier = m_aAsicVerifierFactory.verify (ClassPathResource.getInputStream ("/asic/asic-xades-external-digidoc4j.asice")))
    {
      assertEquals (asicVerifier.getAsicManifest ().getFile ().size (), 2);
      assertNotNull (asicVerifier.getOasisManifest ());
    }
  }

  // Fetched from
  // https://github.com/esig/dss/blob/master/dss-asic/src/test/resources/plugtest/esig2014/ESIG-ASiC/EE_AS/Signature-A-EE_AS-1.asice
  @Test
  public void validDss () throws IOException
  {
    try (final AsicVerifier asicVerifier = m_aAsicVerifierFactory.verify (ClassPathResource.getInputStream ("/asic/asic-xades-external-dss.asice")))
    {
      assertEquals (asicVerifier.getAsicManifest ().getFile ().size (), 1);
      assertNotNull (asicVerifier.getOasisManifest ());
    }
  }

  @Test
  @Ignore
  public void invalidManifest () throws IOException
  {
    try
    {
      m_aAsicVerifierFactory.verify (ClassPathResource.getInputStream ("/asic/asic-xades-invalid-manifest.asice"));
      fail ("Exception expected.");
    }
    catch (final IllegalStateException e)
    {
      // Ignore
    }
  }

  @Test
  @Ignore
  public void invalidSignature () throws IOException
  {
    try
    {
      m_aAsicVerifierFactory.verify (ClassPathResource.getInputStream ("/asic/asic-xades-invalid-signature.asice"));
      fail ("Exception expected.");
    }
    catch (final IllegalStateException e)
    {
      // Ignore
    }
  }

  @Test
  @Ignore
  public void invalidSignedProperties () throws IOException
  {
    try
    {
      m_aAsicVerifierFactory.verify (ClassPathResource.getInputStream ("/asic/asic-xades-invalid-signedproperties.asice"));
      fail ("Exception expected.");
    }
    catch (final IllegalStateException e)
    {
      // Ignore
    }
  }
}
