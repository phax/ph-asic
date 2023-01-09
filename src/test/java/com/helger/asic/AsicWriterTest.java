/*
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018-2023 Philip Helger (www.helger.com)
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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.asic.jaxb.asic.AsicManifest;
import com.helger.asic.jaxb.cades.DataObjectReferenceType;
import com.helger.commons.io.file.FilenameHelper;
import com.helger.commons.io.resource.ClassPathResource;
import com.helger.commons.io.stream.NonBlockingByteArrayOutputStream;
import com.helger.commons.mime.CMimeType;

/**
 * @author steinar Date: 02.07.15 Time: 12.08
 */
public class AsicWriterTest
{
  private static final Logger log = LoggerFactory.getLogger (AsicWriterTest.class);

  private static final String BII_ENVELOPE_XML = "/asic/bii-envelope.xml";
  private static final String BII_MESSAGE_XML = TestUtil.BII_SAMPLE_MESSAGE_XML;

  private AsicVerifierFactory m_aAsicVerifierFactory;
  private File m_aEnvelopeFile;
  private File m_aMessageFile;

  @Before
  public void setUp ()
  {
    m_aEnvelopeFile = ClassPathResource.getAsFile (BII_ENVELOPE_XML);
    m_aMessageFile = ClassPathResource.getAsFile (BII_MESSAGE_XML);

    // Assumes default signature method
    m_aAsicVerifierFactory = AsicVerifierFactory.newFactory ();
  }

  @Test
  public void createSampleContainer () throws Exception
  {

    // PART 1 - creates the ASiC archive

    // Name of the file to hold the the ASiC archive
    final File archiveOutputFile = new File (System.getProperty ("java.io.tmpdir"), "asic-sample-default.zip");

    // Creates an AsicWriterFactory with default signature method
    final AsicWriterFactory asicWriterFactory = AsicWriterFactory.newFactory (ESignatureMethod.CAdES);

    /*
     * Creates the actual container with all the data objects (files) and signs
     * it.
     */
    final IAsicWriter asicWriter = asicWriterFactory.newContainer (archiveOutputFile);
    /*
     * Adds an ordinary file, using the file name as the entry name
     */
    asicWriter.add (m_aEnvelopeFile);
    /*
     * Adds another file, explicitly naming the entry and specifying the MIME
     * type
     */
    asicWriter.add (m_aMessageFile, BII_MESSAGE_XML, CMimeType.APPLICATION_XML);
    /*
     * Indicates that the BII message is the root document
     */
    asicWriter.setRootEntryName (BII_MESSAGE_XML);
    /*
     * Signing the contents of the archive, closes it for further changes.
     */
    asicWriter.sign (TestUtil.createSH ());

    // PART 2 - verify the contents of the archive.

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

    assertTrue ("ASiC container can not be read", archiveOutputFile.canRead ());

    if (log.isInfoEnabled ())
      log.info ("Generated file " + archiveOutputFile);

    try (final ZipFile zipFile = new ZipFile (archiveOutputFile))
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
      asicWriter.add (m_aEnvelopeFile);
      fail ("Exception expected");
    }
    catch (final IllegalStateException e)
    {
      // okay
    }

    try
    {
      asicWriter.sign (TestUtil.createSH ());
      fail ("Exception expected");
    }
    catch (final IllegalStateException e)
    {
      // ignore
    }

    try (final AsicVerifier asicVerifier = m_aAsicVerifierFactory.verify (archiveOutputFile))
    {
      assertEquals (asicVerifier.getAsicManifest ().getFile ().size (), 2);
    }
  }

  @Test
  public void writeAndRead () throws Exception
  {
    final File brochurePdfFile = ClassPathResource.getAsFile ("/asic/e-Delivery_target_architecture.pdf");
    assertTrue (brochurePdfFile.canRead ());

    // Name of the file to hold the the ASiC archive
    final File archiveOutputFile = new File (System.getProperty ("java.io.tmpdir"), "asic-sample-default.zip");

    // Creates an AsicWriterFactory with default signature method
    final AsicWriterFactory asicWriterFactory = AsicWriterFactory.newFactory (ESignatureMethod.CAdES);

    // Creates the actual container with all the data objects (files) and signs
    // it.
    asicWriterFactory.newContainer (archiveOutputFile)
                     // Adds file, explicitly naming the entry and specifying
                     // the MIME type
                     .add (m_aMessageFile, FilenameHelper.getWithoutPath (BII_MESSAGE_XML), CMimeType.APPLICATION_XML)
                     // Indicates which file is the root file
                     .setRootEntryName (FilenameHelper.getWithoutPath (BII_MESSAGE_XML))
                     // Adds a PDF attachment, using the name of the file, i.e.
                     // with path removed, as the entry name
                     .add (brochurePdfFile)
                     // Signing the contents of the archive, closes it for
                     // further changes.
                     .sign (TestUtil.createSH ());

    log.debug ("Wrote ASiC-e container to " + archiveOutputFile);
    // Opens the generated archive and reads each entry
    try (final IAsicReader asicReader = AsicReaderFactory.newFactory ().open (archiveOutputFile))
    {
      String entryName;

      // Iterates over each entry and writes the contents into a file having
      // same name as the entry
      while ((entryName = asicReader.getNextFile ()) != null)
      {
        if (log.isDebugEnabled ())
          log.debug ("Read entry " + entryName);

        // Creates file with same name as entry
        final File file = new File (entryName);
        // Ensures we don't overwrite anything
        assertFalse (entryName + " already exists!", file.exists ());

        asicReader.writeFile (file);

        // Removes file immediately, since this is just a test
        file.delete ();
      }

      final AsicManifest asicManifest = asicReader.getAsicManifest ();
      final String asicManifestRootfile = asicManifest.getRootfile ();
      assertNotNull (asicManifestRootfile, "Root file not found");
      assertEquals ("Invalid Rootfile found", asicManifestRootfile, FilenameHelper.getWithoutPath (BII_MESSAGE_XML));
    }
  }

  @Test
  public void unknownMimetype () throws Exception
  {
    try
    {
      final AsicWriterFactory asicWriterFactory = AsicWriterFactory.newFactory (ESignatureMethod.CAdES);
      try (final NonBlockingByteArrayOutputStream aBAOS = new NonBlockingByteArrayOutputStream ())
      {
        asicWriterFactory.newContainer (aBAOS).add (m_aEnvelopeFile, "envelope.aaz");
        fail ("Expected exception, is .aaz a known extension?");
      }
    }
    catch (final IllegalStateException e)
    {
      // expected
    }
  }
}
