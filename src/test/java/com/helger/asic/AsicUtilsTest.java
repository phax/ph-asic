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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.commons.io.stream.NonBlockingByteArrayInputStream;
import com.helger.commons.io.stream.NonBlockingByteArrayOutputStream;
import com.helger.commons.mime.CMimeType;

public final class AsicUtilsTest
{
  private static final Logger log = LoggerFactory.getLogger (AsicUtilsTest.class);

  private final AsicReaderFactory m_aAsicReaderFactory = AsicReaderFactory.newFactory ();
  private final AsicWriterFactory m_aAsicWriterFactory = AsicWriterFactory.newFactory (ESignatureMethod.CAdES);
  private final SignatureHelper m_aSignatureHelper = TestUtil.createSH ();

  private static final String FILE_CONTENT_1 = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nam arcu eros, fermentum vel molestie ut, sagittis vel velit.";
  private static final String FILE_CONTENT_2 = "Fusce eu risus ipsum. Sed mattis laoreet justo. Fusce nisi magna, posuere ac placerat tincidunt, dignissim non lacus.";

  @Test
  public void validatePatterns ()
  {
    assertTrue (AsicUtils.PATTERN_CADES_MANIFEST.matcher ("META-INF/asicmanifest.xml").matches ());
    assertTrue (AsicUtils.PATTERN_CADES_MANIFEST.matcher ("META-INF/ASICMANIFESTt.xml").matches ());
    assertTrue (AsicUtils.PATTERN_CADES_MANIFEST.matcher ("META-INF/asicmanifest1.xml").matches ());
    assertFalse (AsicUtils.PATTERN_CADES_MANIFEST.matcher ("META-INF/asicmanifesk.xml").matches ());

    assertTrue (AsicUtils.PATTERN_CADES_SIGNATURE.matcher ("META-INF/signature.p7s").matches ());
    assertTrue (AsicUtils.PATTERN_CADES_SIGNATURE.matcher ("META-INF/SIGNATURE.p7s").matches ());
    assertTrue (AsicUtils.PATTERN_CADES_SIGNATURE.matcher ("META-INF/signature-cafecafe.p7s").matches ());
    assertFalse (AsicUtils.PATTERN_CADES_SIGNATURE.matcher ("META-INF/signatures.xml").matches ());

    assertTrue (AsicUtils.PATTERN_XADES_SIGNATURES.matcher ("META-INF/signatures.xml").matches ());
    assertTrue (AsicUtils.PATTERN_XADES_SIGNATURES.matcher ("META-INF/SIGNATURES.xml").matches ());
    assertTrue (AsicUtils.PATTERN_XADES_SIGNATURES.matcher ("META-INF/signatures1.xml").matches ());
    assertFalse (AsicUtils.PATTERN_XADES_SIGNATURES.matcher ("META-INF/signature.xml").matches ());

    assertTrue (AsicUtils.PATTERN_EXTENSION_ASICE.matcher ("mycontainer.asice").matches ());
    assertFalse (AsicUtils.PATTERN_EXTENSION_ASICE.matcher ("mycontainer.asice3").matches ());
    assertFalse (AsicUtils.PATTERN_EXTENSION_ASICE.matcher ("file://c/Users/skrue/mycontainer.asice3").matches ());
    assertTrue (AsicUtils.PATTERN_EXTENSION_ASICE.matcher ("mycontainer.sce").matches ());
  }

  @Test
  public void simpleCombine () throws IOException
  {
    // Create first container
    final NonBlockingByteArrayOutputStream source1 = new NonBlockingByteArrayOutputStream ();
    m_aAsicWriterFactory.newContainer (source1)
                        .add (new NonBlockingByteArrayInputStream (FILE_CONTENT_1.getBytes (StandardCharsets.ISO_8859_1)),
                              "content1.txt",
                              CMimeType.TEXT_PLAIN)
                        .sign (m_aSignatureHelper);

    // Create second container
    final NonBlockingByteArrayOutputStream source2 = new NonBlockingByteArrayOutputStream ();
    m_aAsicWriterFactory.newContainer (source2)
                        .add (new NonBlockingByteArrayInputStream (FILE_CONTENT_2.getBytes (StandardCharsets.ISO_8859_1)),
                              "content2.txt",
                              CMimeType.TEXT_PLAIN)
                        .sign (m_aSignatureHelper);

    // Combine containers
    final NonBlockingByteArrayOutputStream target = new NonBlockingByteArrayOutputStream ();
    AsicUtils.combine (target, source1.getAsInputStream (), source2.getAsInputStream ());

    // Read container (asic)
    try (final IAsicReader asicReader = m_aAsicReaderFactory.open (target.getAsInputStream ()))
    {
      NonBlockingByteArrayOutputStream fileStream;
      {
        assertEquals (asicReader.getNextFile (), "content1.txt");

        fileStream = new NonBlockingByteArrayOutputStream ();
        asicReader.writeFile (fileStream);
        assertEquals (fileStream.getAsString (StandardCharsets.ISO_8859_1), FILE_CONTENT_1);
      }

      {
        assertEquals (asicReader.getNextFile (), "content2.txt");

        fileStream = new NonBlockingByteArrayOutputStream ();
        asicReader.writeFile (fileStream);
        assertEquals (fileStream.getAsString (StandardCharsets.ISO_8859_1), FILE_CONTENT_2);
      }

      assertNull (asicReader.getNextFile ());
    }

    // Read container (zip)
    try (final ZipInputStream zipInputStream = new ZipInputStream (target.getAsInputStream ()))
    {
      assertEquals (zipInputStream.getNextEntry ().getName (), "mimetype");
      assertEquals (zipInputStream.getNextEntry ().getName (), "content1.txt");
      assertEquals (zipInputStream.getNextEntry ().getName (),
                    "META-INF/" + AsicUtils.ASIC_MANIFEST_BASENAME + "1.xml");
      assertTrue (AsicUtils.PATTERN_CADES_SIGNATURE.matcher (zipInputStream.getNextEntry ().getName ()).matches ());
      assertEquals (zipInputStream.getNextEntry ().getName (), "content2.txt");
      assertEquals (zipInputStream.getNextEntry ().getName (),
                    "META-INF/" + AsicUtils.ASIC_MANIFEST_BASENAME + "2.xml");
      assertTrue (AsicUtils.PATTERN_CADES_SIGNATURE.matcher (zipInputStream.getNextEntry ().getName ()).matches ());
      assertEquals (zipInputStream.getNextEntry ().getName (), "META-INF/manifest.xml");
      assertNull (zipInputStream.getNextEntry ());
    }
  }

  @Test
  public void combineWhereOnlyOneHasManifest () throws IOException
  {
    // Create first container
    final NonBlockingByteArrayOutputStream source1 = new NonBlockingByteArrayOutputStream ();
    m_aAsicWriterFactory.newContainer (source1)
                        .add (new NonBlockingByteArrayInputStream (FILE_CONTENT_1.getBytes (StandardCharsets.ISO_8859_1)),
                              "content1.txt",
                              CMimeType.TEXT_PLAIN)
                        .sign (m_aSignatureHelper);

    // Create second container
    final NonBlockingByteArrayOutputStream source2 = new NonBlockingByteArrayOutputStream ();
    m_aAsicWriterFactory.newContainer (source2)
                        .add (new NonBlockingByteArrayInputStream (FILE_CONTENT_2.getBytes (StandardCharsets.ISO_8859_1)),
                              "content2.txt",
                              CMimeType.TEXT_PLAIN)
                        .sign (m_aSignatureHelper);

    // Rewrite source2 to remove META-INF/manifest.xml
    try (final NonBlockingByteArrayOutputStream source2simpler = new NonBlockingByteArrayOutputStream ())
    {
      try (final AsicInputStream source2input = new AsicInputStream (source2.getAsInputStream ());
           final AsicOutputStream source2output = new AsicOutputStream (source2simpler))
      {
        ZipEntry zipEntry;
        while ((zipEntry = source2input.getNextEntry ()) != null)
        {
          if (!zipEntry.getName ().equals ("META-INF/manifest.xml"))
          {
            source2output.putNextEntry (zipEntry);
            AsicUtils.copyStream (source2input, source2output);
            source2output.closeEntry ();
            source2input.closeEntry ();
          }
        }
      }

      // Combine containers
      final NonBlockingByteArrayOutputStream target = new NonBlockingByteArrayOutputStream ();
      AsicUtils.combine (target, source1.getAsInputStream (), source2simpler.getAsInputStream ());

      // Read container (zip)
      try (final ZipInputStream zipInputStream = new ZipInputStream (target.getAsInputStream ()))
      {
        assertEquals (zipInputStream.getNextEntry ().getName (), "mimetype");
        assertEquals (zipInputStream.getNextEntry ().getName (), "content1.txt");
        assertEquals (zipInputStream.getNextEntry ().getName (),
                      "META-INF/" + AsicUtils.ASIC_MANIFEST_BASENAME + "1.xml");
        assertTrue (AsicUtils.PATTERN_CADES_SIGNATURE.matcher (zipInputStream.getNextEntry ().getName ()).matches ());
        assertEquals (zipInputStream.getNextEntry ().getName (), "content2.txt");
        assertEquals (zipInputStream.getNextEntry ().getName (),
                      "META-INF/" + AsicUtils.ASIC_MANIFEST_BASENAME + "2.xml");
        assertTrue (AsicUtils.PATTERN_CADES_SIGNATURE.matcher (zipInputStream.getNextEntry ().getName ()).matches ());
        assertNull (zipInputStream.getNextEntry ());
      }
    }
  }

  @Test
  public void simpleMultipleRootfiles () throws IOException
  {
    // Create first container
    final NonBlockingByteArrayOutputStream source1 = new NonBlockingByteArrayOutputStream ();
    m_aAsicWriterFactory.newContainer (source1)
                        .add (new NonBlockingByteArrayInputStream (FILE_CONTENT_1.getBytes (StandardCharsets.ISO_8859_1)),
                              "content1.txt",
                              CMimeType.TEXT_PLAIN)
                        .setRootEntryName ("content1.txt")
                        .sign (m_aSignatureHelper);

    // Create second container
    final NonBlockingByteArrayOutputStream source2 = new NonBlockingByteArrayOutputStream ();
    m_aAsicWriterFactory.newContainer (source2)
                        .add (new NonBlockingByteArrayInputStream (FILE_CONTENT_2.getBytes (StandardCharsets.ISO_8859_1)),
                              "content2.txt",
                              CMimeType.TEXT_PLAIN)
                        .setRootEntryName ("content2.txt")
                        .sign (m_aSignatureHelper);

    // Combine containers
    try
    {
      AsicUtils.combine (new NonBlockingByteArrayOutputStream (),
                         source1.getAsInputStream (),
                         source2.getAsInputStream ());
      fail ("Exception expected.");
    }
    catch (final IllegalStateException e)
    {
      log.info (e.getMessage ());
    }
  }

  @SuppressWarnings ("deprecation")
  @Test
  public void simpleCombineXades () throws IOException
  {
    final AsicWriterFactory aFactoryXades = AsicWriterFactory.newFactory (ESignatureMethod.XAdES);

    // Create first container
    final NonBlockingByteArrayOutputStream source1 = new NonBlockingByteArrayOutputStream ();
    aFactoryXades.newContainer (source1)
                 .add (new NonBlockingByteArrayInputStream (FILE_CONTENT_1.getBytes (StandardCharsets.ISO_8859_1)),
                       "content1.txt",
                       CMimeType.TEXT_PLAIN)
                 .sign (m_aSignatureHelper);

    // Create second container
    final NonBlockingByteArrayOutputStream source2 = new NonBlockingByteArrayOutputStream ();
    aFactoryXades.newContainer (source2)
                 .add (new NonBlockingByteArrayInputStream (FILE_CONTENT_2.getBytes (StandardCharsets.ISO_8859_1)),
                       "content2.txt",
                       CMimeType.TEXT_PLAIN)
                 .sign (m_aSignatureHelper);

    // Combine containers
    final NonBlockingByteArrayOutputStream target = new NonBlockingByteArrayOutputStream ();
    AsicUtils.combine (target, source1.getAsInputStream (), source2.getAsInputStream ());

    // Read container (asic)
    try (final IAsicReader asicReader = m_aAsicReaderFactory.open (target.getAsInputStream ()))
    {
      NonBlockingByteArrayOutputStream fileStream;
      {
        assertEquals (asicReader.getNextFile (), "content1.txt");

        fileStream = new NonBlockingByteArrayOutputStream ();
        asicReader.writeFile (fileStream);
        assertEquals (fileStream.getAsString (StandardCharsets.ISO_8859_1), FILE_CONTENT_1);
      }

      {
        assertEquals (asicReader.getNextFile (), "content2.txt");

        fileStream = new NonBlockingByteArrayOutputStream ();
        asicReader.writeFile (fileStream);
        assertEquals (fileStream.getAsString (StandardCharsets.ISO_8859_1), FILE_CONTENT_2);
      }

      assertNull (asicReader.getNextFile ());
    }

    // Read container (zip)
    try (final ZipInputStream zipInputStream = new ZipInputStream (target.getAsInputStream ()))
    {
      assertEquals (zipInputStream.getNextEntry ().getName (), "mimetype");
      assertEquals (zipInputStream.getNextEntry ().getName (), "content1.txt");
      assertEquals (zipInputStream.getNextEntry ().getName (), "META-INF/signatures1.xml");
      assertEquals (zipInputStream.getNextEntry ().getName (), "content2.txt");
      assertEquals (zipInputStream.getNextEntry ().getName (), "META-INF/signatures2.xml");
      assertEquals (zipInputStream.getNextEntry ().getName (), "META-INF/manifest.xml");
      assertNull (zipInputStream.getNextEntry ());
    }
  }
}
