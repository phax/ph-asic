/**
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018-2020 Philip Helger (www.helger.com)
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
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.asic.jaxb.asic.AsicManifest;
import com.helger.commons.io.resource.ClassPathResource;
import com.helger.commons.io.stream.NonBlockingByteArrayOutputStream;

public final class AsicCadesReferenceTest
{
  private static final Logger LOGGER = LoggerFactory.getLogger (AsicCadesReferenceTest.class);

  private final AsicVerifierFactory m_aAsicVerifierFactory = AsicVerifierFactory.newFactory (EMessageDigestAlgorithm.DEFAULT);
  private final AsicReaderFactory m_aAsicRederFactory = AsicReaderFactory.newFactory (EMessageDigestAlgorithm.DEFAULT);

  @Test
  public void valid () throws Exception
  {
    try (
        final AsicVerifier asicVerifier = m_aAsicVerifierFactory.verify (ClassPathResource.getInputStream ("/asic/asic-cades-test-valid.asice")))
    {
      assertEquals (asicVerifier.getAsicManifest ().getFile ().size (), 2);

      // Printing internal manifest for reference.
      final JAXBContext jaxbContext = JAXBContext.newInstance (AsicManifest.class);
      final Marshaller aMarshaller = jaxbContext.createMarshaller ();
      aMarshaller.setProperty (Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);

      try (final NonBlockingByteArrayOutputStream aNBBAOS = new NonBlockingByteArrayOutputStream ())
      {
        aMarshaller.marshal (asicVerifier.getAsicManifest (), aNBBAOS);
        LOGGER.info (aNBBAOS.getAsString (StandardCharsets.UTF_8));
      }
    }
  }

  @Test
  public void invalidManifest () throws IOException
  {
    try
    {
      m_aAsicVerifierFactory.verify (ClassPathResource.getInputStream ("/asic/asic-cades-test-invalid-manifest.asice"));
      fail ("Exception expected.");
    }
    catch (final IllegalStateException e)
    {
      // empty
    }

    try (
        final IAsicReader asicReader = m_aAsicRederFactory.open (ClassPathResource.getInputStream ("/asic/asic-cades-test-invalid-manifest.asice")))
    {
      asicReader.getNextFile ();
      fail ("Exception expected");
    }
    catch (final IllegalStateException e)
    {
      // Container doesn't contain content files, so first read is expected to
      // find manifest and thus throw exception.
    }
  }

  @Test
  public void invalidSignature () throws IOException
  {
    try
    {
      m_aAsicVerifierFactory.verify (ClassPathResource.getInputStream ("/asic/asic-cades-test-invalid-signature.asice"));
      fail ("Exception expected.");
    }
    catch (final IllegalStateException e)
    {
      LOGGER.info (e.getMessage ());
    }
  }

  @Test
  public void invalidMetadataFile () throws IOException
  {
    try
    {
      m_aAsicVerifierFactory.verify (ClassPathResource.getInputStream ("/asic/asic-cades-test-invalid-metadata-file.asice"));
      fail ("Exception expected.");
    }
    catch (final IllegalStateException e)
    {
      assertTrue (e.getMessage ().contains ("signature.malformed"));
    }
  }

  @Test // (enabled = false)
  public void invalidSigReference () throws IOException
  {
    try
    {
      m_aAsicVerifierFactory.verify (ClassPathResource.getInputStream ("/asic/asic-cades-test-invalid-sigreference.asice"));
      fail ("Exception expected.");
    }
    catch (final IllegalStateException e)
    {
      // expected
    }
  }
}
