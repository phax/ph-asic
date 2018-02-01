package no.difi.asic;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.xsds.xmldsig.ReferenceType;

/**
 * @author steinar Date: 02.07.15 Time: 12.08
 */
public class AsicXadesWriterTest
{

  public static final Logger log = LoggerFactory.getLogger (AsicXadesWriterTest.class);

  public static final String BII_ENVELOPE_XML = "bii-envelope.xml";
  public static final String BII_MESSAGE_XML = TestUtil.BII_SAMPLE_MESSAGE_XML;
  private URL envelopeUrl;
  private URL messageUrl;
  private File keystoreFile;

  private AsicWriterFactory asicContainerWriterFactory;

  @Before
  public void setUp ()
  {
    envelopeUrl = AsicXadesWriterTest.class.getClassLoader ().getResource (BII_ENVELOPE_XML);
    assertNotNull (envelopeUrl);

    messageUrl = AsicXadesWriterTest.class.getClassLoader ().getResource (BII_MESSAGE_XML);
    assertNotNull (messageUrl);

    keystoreFile = new File ("src/test/resources/keystore.jks");
    assertTrue ("Expected to find your private key and certificate in " + keystoreFile, keystoreFile.canRead ());

    asicContainerWriterFactory = AsicWriterFactory.newFactory (ESignatureMethod.XAdES);
  }

  @Test
  public void createSampleEmptyContainer () throws Exception
  {
    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream ();
    asicContainerWriterFactory.newContainer (outputStream).sign (keystoreFile, "changeit", "changeit");

    final byte [] buffer = outputStream.toByteArray ();
    assertEquals ("Byte 28 should be 0", buffer[28], (byte) 0);
    assertEquals ("'mimetype' file should not be compressed", buffer[8], 0);
    assertTrue ("First 4 octets should read 0x50 0x4B 0x03 0x04",
                buffer[0] == 0x50 && buffer[1] == 0x4B && buffer[2] == 0x03 && buffer[3] == 0x04);
  }

  @Test
  public void createSampleContainer () throws Exception
  {
    final SignatureHelper signatureHelper = new SignatureHelper (keystoreFile, "changeit", "selfsigned", "changeit");

    final IAsicWriter asicWriter = asicContainerWriterFactory.newContainer (new File (System.getProperty ("java.io.tmpdir")),
                                                                           "asic-sample-xades.zip")
                                                            .add (new File (envelopeUrl.toURI ()))
                                                            .add (new File (messageUrl.toURI ()),
                                                                  TestUtil.BII_SAMPLE_MESSAGE_XML,
                                                                  MimeType.forString ("application/xml"))
                                                            .sign (signatureHelper);

    final File file = new File (System.getProperty ("java.io.tmpdir"), "asic-sample-xades.zip");

    // Verifies that both files have been added.
    {
      int matchCount = 0;
      final XadesAsicManifest asicManifest = (XadesAsicManifest) ((XadesAsicWriter) asicWriter).getAsicManifest ();

      for (final ReferenceType reference : asicManifest.getCreateXAdESSignatures (signatureHelper)
                                                       .getSignature ()
                                                       .get (0)
                                                       .getSignedInfo ()
                                                       .getReference ())
      {
        if (reference.getURI ().equals (BII_ENVELOPE_XML))
          matchCount++;
        if (reference.getURI ().equals (BII_MESSAGE_XML))
          matchCount++;
      }
      assertEquals ("Entries were not added properly into list", matchCount, 2);
    }

    assertTrue ("ASiC container can not be read", file.canRead ());

    log.info ("Generated file " + file);

    final ZipFile zipFile = new ZipFile (file);
    final Enumeration <? extends ZipEntry> entries = zipFile.entries ();

    {
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
      asicWriter.sign (keystoreFile, "changeit", "changeit");
      fail ("Exception expected");
    }
    catch (final Exception e)
    {
      assertTrue (e instanceof IllegalStateException);
    }
  }

  @Test
  public void rootfileNotSupported () throws IOException
  {
    final IAsicWriter asicWriter = asicContainerWriterFactory.newContainer (new ByteArrayOutputStream ());
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
