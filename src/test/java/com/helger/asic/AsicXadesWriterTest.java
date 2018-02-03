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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.commons.io.file.FilenameHelper;
import com.helger.commons.io.resource.ClassPathResource;
import com.helger.commons.mime.CMimeType;
import com.helger.xsds.xmldsig.ReferenceType;

/**
 * @author steinar Date: 02.07.15 Time: 12.08
 */
public final class AsicXadesWriterTest
{
  private static final Logger log = LoggerFactory.getLogger (AsicXadesWriterTest.class);

  public static final String BII_ENVELOPE_XML = "/asic/bii-envelope.xml";
  public static final String BII_MESSAGE_XML = TestUtil.BII_SAMPLE_MESSAGE_XML;
  private File m_aEnvelopeFile;
  private File m_aMessageFile;
  private File m_aKeystoreFile;

  private AsicWriterFactory m_aAsicWriterFactory;

  @Before
  public void setUp ()
  {
    m_aEnvelopeFile = new ClassPathResource (BII_ENVELOPE_XML).getAsFile ();
    assertNotNull (m_aEnvelopeFile);

    m_aMessageFile = new ClassPathResource (BII_MESSAGE_XML).getAsFile ();
    assertNotNull (m_aMessageFile);

    m_aKeystoreFile = TestUtil.keyStoreFile ();
    assertTrue ("Expected to find your private key and certificate in " + m_aKeystoreFile, m_aKeystoreFile.canRead ());

    m_aAsicWriterFactory = AsicWriterFactory.newFactory (ESignatureMethod.XAdES);
  }

  @Test
  public void createSampleEmptyContainer () throws Exception
  {
    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream ();
    m_aAsicWriterFactory.newContainer (outputStream).sign (m_aKeystoreFile, "changeit", "changeit");

    final byte [] buffer = outputStream.toByteArray ();
    assertEquals ("Byte 28 should be 0", buffer[28], (byte) 0);
    assertEquals ("'mimetype' file should not be compressed", buffer[8], 0);
    assertTrue ("First 4 octets should read 0x50 0x4B 0x03 0x04",
                buffer[0] == 0x50 && buffer[1] == 0x4B && buffer[2] == 0x03 && buffer[3] == 0x04);
  }

  @Test
  public void createSampleContainer () throws Exception
  {
    final SignatureHelper signatureHelper = new SignatureHelper (m_aKeystoreFile, "changeit", "selfsigned", "changeit");

    final IAsicWriter asicWriter = m_aAsicWriterFactory.newContainer (new File (System.getProperty ("java.io.tmpdir")),
                                                                      "asic-sample-xades.zip")
                                                       .add (m_aEnvelopeFile)
                                                       .add (m_aMessageFile,
                                                             TestUtil.BII_SAMPLE_MESSAGE_XML,
                                                             CMimeType.APPLICATION_XML)
                                                       .sign (signatureHelper);

    final File file = new File (System.getProperty ("java.io.tmpdir"), "asic-sample-xades.zip");

    // Verifies that both files have been added.
    {
      int matchCount = 0;
      final XadesAsicManifest asicManifest = ((XadesAsicWriter) asicWriter).getAsicManifest ();

      for (final ReferenceType reference : asicManifest.getCreateXAdESSignatures (signatureHelper)
                                                       .getSignature ()
                                                       .get (0)
                                                       .getSignedInfo ()
                                                       .getReference ())
      {
        if (reference.getURI ().equals (FilenameHelper.getWithoutPath (BII_ENVELOPE_XML)))
          matchCount++;
        if (reference.getURI ().equals (BII_MESSAGE_XML))
          matchCount++;
      }
      assertEquals ("Entries were not added properly into list", matchCount, 2);
    }

    assertTrue ("ASiC container can not be read", file.canRead ());

    log.info ("Generated file " + file);

    try (final ZipFile zipFile = new ZipFile (file))
    {
      final Enumeration <? extends ZipEntry> entries = zipFile.entries ();

      {
        int matchCount = 0;
        while (entries.hasMoreElements ())
        {
          final ZipEntry entry = entries.nextElement ();
          final String name = entry.getName ();
          if (FilenameHelper.getWithoutPath (BII_ENVELOPE_XML).equals (name))
          {
            matchCount++;
          }
          if (BII_MESSAGE_XML.equals (name))
          {
            matchCount++;
          }
          log.info ("Found " + name);
        }
        assertEquals ("Number of items in archive did not match", matchCount, 2);
      }
    }
    try
    {
      asicWriter.add (m_aEnvelopeFile);
      fail ("Exception expected");
    }
    catch (final IllegalStateException e)
    {
      // fail
    }

    try
    {
      asicWriter.sign (m_aKeystoreFile, "changeit", "changeit");
      fail ("Exception expected");
    }
    catch (final IllegalStateException e)
    {
      // fail
    }
  }

  @Test
  public void rootfileNotSupported () throws IOException
  {
    final IAsicWriter asicWriter = m_aAsicWriterFactory.newContainer (new ByteArrayOutputStream ());
    asicWriter.add (new ByteArrayInputStream ("Content".getBytes ()), "rootfile.txt");

    try
    {
      asicWriter.setRootEntryName ("rootfile.txt");
      fail ("Exception expected.");
    }
    catch (final IllegalStateException e)
    {
      log.info (e.getMessage ());
    }
  }
}
