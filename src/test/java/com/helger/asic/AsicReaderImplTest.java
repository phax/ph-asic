/**
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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.commons.io.resource.ClassPathResource;
import com.helger.commons.io.stream.NonBlockingByteArrayOutputStream;
import com.helger.commons.io.stream.StringInputStream;
import com.helger.commons.mime.CMimeType;

public class AsicReaderImplTest
{
  private static final Logger log = LoggerFactory.getLogger (AsicReaderImplTest.class);

  private final AsicReaderFactory m_aAsicReaderFactory = AsicReaderFactory.newFactory ();
  private final AsicWriterFactory m_aAsicWriterFactory = AsicWriterFactory.newFactory (ESignatureMethod.CAdES);
  private static final SignatureHelper m_aSignatureHelper = TestUtil.createSH ();

  private static final String FILE_CONTENT_1 = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nam arcu eros, fermentum vel molestie ut, sagittis vel velit.";
  private static final String FILE_CONTENT_2 = "Fusce eu risus ipsum. Sed mattis laoreet justo. Fusce nisi magna, posuere ac placerat tincidunt, dignissim non lacus.";

  @Test
  public void writeAndReadSimpleContainer () throws IOException
  {
    // Step 1 - creates the ASiC archive
    final NonBlockingByteArrayOutputStream containerOutput = new NonBlockingByteArrayOutputStream ();

    m_aAsicWriterFactory.newContainer (containerOutput)
                        .add (new StringInputStream (FILE_CONTENT_1, StandardCharsets.ISO_8859_1),
                              "content1.txt",
                              CMimeType.TEXT_PLAIN)
                        .add (new StringInputStream (FILE_CONTENT_2, StandardCharsets.ISO_8859_1),
                              "content2.txt",
                              CMimeType.TEXT_PLAIN)
                        .sign (m_aSignatureHelper);

    // Step 2 - reads the contents of the ASiC archive
    try (final IAsicReader asicReader = m_aAsicReaderFactory.open (containerOutput.getAsInputStream ()))
    {
      NonBlockingByteArrayOutputStream fileStream;
      {
        assertEquals ("content1.txt", asicReader.getNextFile ());

        fileStream = new NonBlockingByteArrayOutputStream ();
        asicReader.writeFile (fileStream);
        assertEquals (FILE_CONTENT_1, fileStream.getAsString (StandardCharsets.ISO_8859_1));
      }

      {
        assertEquals ("content2.txt", asicReader.getNextFile ());

        fileStream = new NonBlockingByteArrayOutputStream ();
        asicReader.writeFile (fileStream);
        assertEquals (FILE_CONTENT_2, fileStream.getAsString (StandardCharsets.ISO_8859_1));
      }

      assertNull (asicReader.getNextFile ());

      try
      {
        asicReader.writeFile (new NonBlockingByteArrayOutputStream ());
        fail ("Exception expected");
      }
      catch (final IllegalStateException e)
      {
        // expected
      }

      asicReader.close ();

      try
      {
        // Try again
        asicReader.close ();
      }
      catch (final IllegalStateException e)
      {
        fail ("No exception expected");
      }

      assertEquals (asicReader.getAsicManifest ().getFile ().size (), 2);
    }
  }

  @Test
  public void writeAndReadSimpleFileContainer () throws IOException
  {
    final File tmpDir = new File (System.getProperty ("java.io.tmpdir"));

    final File file = new File (tmpDir, "asic-reader-sample.ip");

    m_aAsicWriterFactory.newContainer (file)
                        .add (new StringInputStream (FILE_CONTENT_1, StandardCharsets.ISO_8859_1),
                              "content1.txt",
                              CMimeType.TEXT_PLAIN)
                        .add (new StringInputStream (FILE_CONTENT_2, StandardCharsets.ISO_8859_1),
                              "content2.txt",
                              CMimeType.TEXT_PLAIN)
                        .sign (m_aSignatureHelper);

    try (final IAsicReader asicReader = m_aAsicReaderFactory.open (file))
    {
      File contentFile;
      String filename;
      NonBlockingByteArrayOutputStream fileStream;
      {
        filename = asicReader.getNextFile ();
        assertEquals ("content1.txt", filename);

        contentFile = new File (tmpDir, "asic-" + filename);
        asicReader.writeFile (contentFile);

        fileStream = new NonBlockingByteArrayOutputStream ();
        AsicUtils.copyStream (Files.newInputStream (contentFile.toPath ()), fileStream);
        assertEquals (FILE_CONTENT_1, fileStream.getAsString (StandardCharsets.ISO_8859_1));

        Files.delete (contentFile.toPath ());
      }

      {
        filename = asicReader.getNextFile ();
        assertEquals ("content2.txt", filename);

        contentFile = new File (tmpDir, "asic-" + filename);
        asicReader.writeFile (contentFile);

        fileStream = new NonBlockingByteArrayOutputStream ();
        AsicUtils.copyStream (Files.newInputStream (contentFile.toPath ()), fileStream);
        assertEquals (FILE_CONTENT_2, fileStream.getAsString (StandardCharsets.ISO_8859_1));

        Files.delete (contentFile.toPath ());
      }

      assertNull (asicReader.getNextFile ());

      try
      {
        asicReader.writeFile (new NonBlockingByteArrayOutputStream ());
        fail ("Exception expected");
      }
      catch (final IllegalStateException e)
      {
        // Expected
      }

      asicReader.close ();

      try
      {
        asicReader.close ();
      }
      catch (final IllegalStateException e)
      {
        fail ("No exception expected");
      }
    }

    Files.delete (file.toPath ());
  }

  @Test
  public void exceptionOnInvalidMime () throws IOException
  {
    try (final IAsicReader asicReader = m_aAsicReaderFactory.open (ClassPathResource.getInputStream ("/asic/asic-general-test-invalid-mime.asice")))
    {
      asicReader.getNextFile ();
      fail ("Didn't throw exception on wrong mimetype.");
    }
    catch (final IllegalStateException e)
    {
      log.info (e.getMessage ());
    }
  }
}
