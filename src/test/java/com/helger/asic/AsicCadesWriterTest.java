/*
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018-2024 Philip Helger (www.helger.com)
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
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.asic.jaxb.cades.DataObjectReferenceType;
import com.helger.commons.io.file.FilenameHelper;
import com.helger.commons.io.resource.ClassPathResource;
import com.helger.commons.io.stream.NonBlockingBufferedInputStream;
import com.helger.commons.io.stream.NonBlockingByteArrayInputStream;
import com.helger.commons.io.stream.NonBlockingByteArrayOutputStream;
import com.helger.commons.mime.CMimeType;

/**
 * @author steinar Date: 02.07.15 Time: 12.08
 */
public final class AsicCadesWriterTest
{
  private static final Logger log = LoggerFactory.getLogger (AsicCadesWriterTest.class);

  public static final int BYTES_TO_CHECK = 40;
  public static final String BII_ENVELOPE_XML = "external/asic/bii-envelope.xml";
  public static final String BII_MESSAGE_XML = TestUtil.BII_SAMPLE_MESSAGE_XML;
  private File m_aEnvelopeFile;
  private File m_aMessageFile;

  private AsicWriterFactory m_aWriterFactory;
  private AsicVerifierFactory m_aVerifierFactory;

  @Before
  public void setUp ()
  {
    m_aEnvelopeFile = ClassPathResource.getAsFile (BII_ENVELOPE_XML);
    assertNotNull (m_aEnvelopeFile);

    m_aMessageFile = ClassPathResource.getAsFile (BII_MESSAGE_XML);
    assertNotNull (m_aMessageFile);

    m_aWriterFactory = AsicWriterFactory.newFactory (ESignatureMethod.CAdES);
    m_aVerifierFactory = AsicVerifierFactory.newFactory ();
  }

  @Test
  public void createSampleEmptyContainer () throws Exception
  {
    for (final EMessageDigestAlgorithm e : EMessageDigestAlgorithm.values ())
    {
      final File aDestFile = new File (System.getProperty ("java.io.tmpdir"), "asic-empty-sample-cades.zip");

      // A container MUST contain any entry
      m_aWriterFactory.setMDAlgo (e).newContainer (aDestFile).add (m_aMessageFile).sign (TestUtil.createSH ());

      assertTrue (aDestFile + " can not be read", aDestFile.exists () && aDestFile.isFile () && aDestFile.canRead ());
      try (final FileInputStream fileInputStream = new FileInputStream (aDestFile);
          final NonBlockingBufferedInputStream is = new NonBlockingBufferedInputStream (fileInputStream))
      {
        final byte [] buffer = new byte [BYTES_TO_CHECK];
        final int read = is.read (buffer, 0, BYTES_TO_CHECK);
        assertEquals (read, BYTES_TO_CHECK);

        assertEquals ("Byte 28 should be 0", buffer[28], (byte) 0);

        assertEquals ("'mimetype' file should not be compressed", buffer[8], 0);

        assertTrue ("First 4 octets should read 0x50 0x4B 0x03 0x04",
                    buffer[0] == 0x50 && buffer[1] == 0x4B && buffer[2] == 0x03 && buffer[3] == 0x04);
      }
      finally
      {
        aDestFile.delete ();
      }
    }
  }

  @Test
  public void createSampleContainer () throws Exception
  {

    final File asicOutputFile = new File (System.getProperty ("java.io.tmpdir"), "asic-sample-cades.zip");

    final IAsicWriter asicWriter = m_aWriterFactory.newContainer (asicOutputFile)
                                                   .add (m_aEnvelopeFile)
                                                   // Specifies the file, the
                                                   // archive entry name and
                                                   // explicitly names the MIME
                                                   // type
                                                   .add (m_aMessageFile, BII_MESSAGE_XML, CMimeType.APPLICATION_XML)
                                                   .setRootEntryName (m_aEnvelopeFile.toURI ().toString ())
                                                   .sign (TestUtil.createSH ());

    // Verifies that both files have been added.
    {
      int matchCount = 0;
      final CadesAsicManifest asicManifest = ((CadesAsicWriter) asicWriter).getAsicManifest ();
      for (final DataObjectReferenceType dataObject : asicManifest.getASiCManifest ().getDataObjectReference ())
      {
        if (dataObject.getURI ().equals (FilenameHelper.getWithoutPath (BII_ENVELOPE_XML)))
          matchCount++;
        if (dataObject.getURI ().equals (BII_MESSAGE_XML))
          matchCount++;
      }
      assertEquals ("Entries were not added properly into list", matchCount, 2);
    }

    assertTrue ("ASiC container can not be read", asicOutputFile.canRead ());

    log.info ("Generated file " + asicOutputFile);

    try (final ZipFile zipFile = new ZipFile (asicOutputFile))
    {
      final Enumeration <? extends ZipEntry> entries = zipFile.entries ();
      int matchCount = 0;
      while (entries.hasMoreElements ())
      {
        final ZipEntry entry = entries.nextElement ();
        final String name = entry.getName ();
        if (FilenameHelper.getWithoutPath (BII_ENVELOPE_XML).equals (name))
        {
          matchCount++;
        }
        else
          if (BII_MESSAGE_XML.equals (name))
          {
            matchCount++;
          }
        log.info ("Found " + name);
        try (final InputStream stream = zipFile.getInputStream (entry))
        {
          // empty
        }
      }
      assertEquals ("Number of items in archive did not match", matchCount, 2);
    }

    try
    {
      asicWriter.add (new File (m_aEnvelopeFile.toURI ()));
      fail ("Exception expected");
    }
    catch (final Exception e)
    {
      assertTrue (e instanceof IllegalStateException);
    }

    try
    {
      asicWriter.sign (TestUtil.createSH ());
      fail ("Exception expected");
    }
    catch (final IllegalStateException e)
    {
      // empty
    }

    try (final AsicVerifier aVerifier = m_aVerifierFactory.verify (asicOutputFile))
    {
      // nada
    }
  }

  @Test
  public void writingToMetaInf () throws IOException
  {
    final IAsicWriter asicWriter = m_aWriterFactory.newContainer (new NonBlockingByteArrayOutputStream ());

    try
    {
      asicWriter.add (new NonBlockingByteArrayInputStream ("Demo".getBytes (StandardCharsets.ISO_8859_1)),
                      "META-INF/demo.xml");
      fail ("Exception expected.");
    }
    catch (final IllegalStateException e)
    {
      // empty
    }
  }
}
