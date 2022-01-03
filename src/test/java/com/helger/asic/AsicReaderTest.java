/*
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018-2022 Philip Helger (www.helger.com)
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
import static org.junit.Assert.fail;

import java.io.IOException;

import org.junit.Test;

import com.helger.commons.io.resource.ClassPathResource;
import com.helger.commons.io.stream.NullOutputStream;

/**
 * Testing functionality.
 */
public final class AsicReaderTest
{
  private final AsicReaderFactory m_aAsicReaderFactory = AsicReaderFactory.newFactory ();

  @Test
  public void readingContentWithWriteFile () throws IOException
  {
    // Testing using AsicReader::writeFile.
    try (final IAsicReader asicReader = m_aAsicReaderFactory.open (ClassPathResource.getInputStream ("/asic/asic-cades-test-valid.asice")))
    {
      while (asicReader.getNextFile () != null)
        asicReader.writeFile (new NullOutputStream ());
      assertEquals (1, asicReader.getAsicManifest ().getCertificate ().size ());
    }
  }

  @Test
  public void readingContentWithInputStream () throws IOException
  {
    // Testing using AsicReader::inputStream.
    try (final IAsicReader asicReader = m_aAsicReaderFactory.open (ClassPathResource.getInputStream ("/asic/asic-cades-test-valid.asice")))
    {
      while (asicReader.getNextFile () != null)
        AsicUtils.copyStream (asicReader.inputStream (), new NullOutputStream ());
      assertEquals (1, asicReader.getAsicManifest ().getCertificate ().size ());
    }
  }

  @Test
  public void readingContentWithoutReading () throws IOException
  {
    // Testing using no functionality to read content.
    try (final IAsicReader asicReader = m_aAsicReaderFactory.open (ClassPathResource.getInputStream ("/asic/asic-cades-test-valid.asice")))
    {
      while (asicReader.getNextFile () != null)
      {
        // No action
      }
      assertEquals (1, asicReader.getAsicManifest ().getCertificate ().size ());
    }
  }

  @Test (expected = IllegalStateException.class)
  public void exceptionOnEmpty () throws IOException
  {
    final IAsicReader asicReader = m_aAsicReaderFactory.open (ClassPathResource.getInputStream ("/asic/asic-cades-test-valid.asice"));
    while (asicReader.getNextFile () != null)
      asicReader.writeFile (new NullOutputStream ());

    // Trigger exception.
    asicReader.inputStream ();

    fail ("Exception not triggered.");
  }
}
