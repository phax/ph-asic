package com.helger.asic;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.asic.jaxb.cades.DataObjectReferenceType;

/**
 * @author steinar Date: 02.07.15 Time: 12.08
 */
public final class AsicCadesWriterTest
{
  private static final Logger log = LoggerFactory.getLogger (AsicCadesWriterTest.class);

  public static final int BYTES_TO_CHECK = 40;
  public static final String BII_ENVELOPE_XML = "bii-envelope.xml";
  public static final String BII_MESSAGE_XML = TestUtil.BII_SAMPLE_MESSAGE_XML;
  private URL envelopeUrl;
  private URL messageUrl;
  private File keystoreFile;

  private AsicWriterFactory asicWriterFactory;
  private AsicVerifierFactory asicVerifierFactory;

  @Before
  public void setUp ()
  {
    envelopeUrl = AsicCadesWriterTest.class.getClassLoader ().getResource (BII_ENVELOPE_XML);
    assertNotNull (envelopeUrl);

    messageUrl = AsicCadesWriterTest.class.getClassLoader ().getResource (BII_MESSAGE_XML);
    assertNotNull (messageUrl);

    keystoreFile = TestUtil.keyStoreFile ();
    assertTrue ("Expected to find your private key and certificate in " + keystoreFile, keystoreFile.canRead ());

    asicWriterFactory = AsicWriterFactory.newFactory ();
    asicVerifierFactory = AsicVerifierFactory.newFactory ();
  }

  @Test
  public void createSampleEmptyContainer () throws Exception
  {

    final File file = new File (System.getProperty ("java.io.tmpdir"), "asic-empty-sample-cades.zip");

    asicWriterFactory.newContainer (file)
                     .sign (keystoreFile, TestUtil.keyStorePassword (), TestUtil.privateKeyPassword ());

    assertTrue (file + " can not be read", file.exists () && file.isFile () && file.canRead ());

    try (final FileInputStream fileInputStream = new FileInputStream (file);
         final BufferedInputStream is = new BufferedInputStream (fileInputStream))
    {
      final byte [] buffer = new byte [BYTES_TO_CHECK];
      final int read = is.read (buffer, 0, BYTES_TO_CHECK);
      assertEquals (read, BYTES_TO_CHECK);

      assertEquals ("Byte 28 should be 0", buffer[28], (byte) 0);

      assertEquals ("'mimetype' file should not be compressed", buffer[8], 0);

      assertTrue ("First 4 octets should read 0x50 0x4B 0x03 0x04",
                  buffer[0] == 0x50 && buffer[1] == 0x4B && buffer[2] == 0x03 && buffer[3] == 0x04);
    }
  }

  @Test
  public void createSampleContainer () throws Exception
  {

    final File asicOutputFile = new File (System.getProperty ("java.io.tmpdir"), "asic-sample-cades.zip");

    final IAsicWriter asicWriter = asicWriterFactory.newContainer (asicOutputFile)
                                                    .add (new File (envelopeUrl.toURI ()))
                                                    // Specifies the file, the
                                                    // archive entry name and
                                                    // explicitly names the MIME
                                                    // type
                                                    .add (new File (messageUrl.toURI ()),
                                                          BII_MESSAGE_XML,
                                                          MimeType.forString ("application/xml"))
                                                    .setRootEntryName (envelopeUrl.toURI ().toString ())
                                                    .sign (keystoreFile,
                                                           TestUtil.keyStorePassword (),
                                                           TestUtil.keyPairAlias (),
                                                           TestUtil.privateKeyPassword ());

    // Verifies that both files have been added.
    {
      int matchCount = 0;
      final CadesAsicManifest asicManifest = (CadesAsicManifest) ((CadesAsicWriter) asicWriter).getAsicManifest ();
      for (final DataObjectReferenceType dataObject : asicManifest.getASiCManifestType ().getDataObjectReference ())
      {
        if (dataObject.getURI ().equals (BII_ENVELOPE_XML))
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
        if (BII_ENVELOPE_XML.equals (name))
        {
          matchCount++;
        }
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
      asicWriter.add (new File (envelopeUrl.toURI ()));
      fail ("Exception expected");
    }
    catch (final Exception e)
    {
      assertTrue (e instanceof IllegalStateException);
    }

    try
    {
      asicWriter.sign (new SignatureHelper (keystoreFile,
                                            TestUtil.keyStorePassword (),
                                            TestUtil.privateKeyPassword ()));
      fail ("Exception expected");
    }
    catch (final Exception e)
    {
      assertTrue (e instanceof IllegalStateException);
    }

    asicVerifierFactory.verify (asicOutputFile);
  }

  @Test
  public void writingToMetaInf () throws IOException
  {
    final IAsicWriter asicWriter = asicWriterFactory.newContainer (new ByteArrayOutputStream ());

    try
    {
      asicWriter.add (new ByteArrayInputStream ("Demo".getBytes ()), "META-INF/demo.xml");
      fail ("Exception expected.");
    }
    catch (final IllegalStateException e)
    {
      log.debug (e.getMessage ());
    }
  }
}
