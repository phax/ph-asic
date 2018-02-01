package com.helger.asic;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AsicUtilsTest
{

  private static Logger log = LoggerFactory.getLogger (AsicUtilsTest.class);

  private final AsicReaderFactory asicReaderFactory = AsicReaderFactory.newFactory ();
  private final AsicWriterFactory asicWriterFactory = AsicWriterFactory.newFactory ();
  private final SignatureHelper signatureHelper = new SignatureHelper (getClass ().getResourceAsStream ("/keystore.jks"),
                                                                       "changeit",
                                                                       null,
                                                                       "changeit");

  private final String fileContent1 = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nam arcu eros, fermentum vel molestie ut, sagittis vel velit.";
  private final String fileContent2 = "Fusce eu risus ipsum. Sed mattis laoreet justo. Fusce nisi magna, posuere ac placerat tincidunt, dignissim non lacus.";

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
    final ByteArrayOutputStream source1 = new ByteArrayOutputStream ();
    asicWriterFactory.newContainer (source1)
                     .add (new ByteArrayInputStream (fileContent1.getBytes ()),
                           "content1.txt",
                           MimeType.forString ("text/plain"))
                     .sign (signatureHelper);

    // Create second container
    final ByteArrayOutputStream source2 = new ByteArrayOutputStream ();
    asicWriterFactory.newContainer (source2)
                     .add (new ByteArrayInputStream (fileContent2.getBytes ()),
                           "content2.txt",
                           MimeType.forString ("text/plain"))
                     .sign (signatureHelper);

    // Combine containers
    final ByteArrayOutputStream target = new ByteArrayOutputStream ();
    AsicUtils.combine (target,
                       new ByteArrayInputStream (source1.toByteArray ()),
                       new ByteArrayInputStream (source2.toByteArray ()));

    // Read container (asic)
    final IAsicReader asicReader = asicReaderFactory.open (new ByteArrayInputStream (target.toByteArray ()));

    ByteArrayOutputStream fileStream;
    {
      assertEquals (asicReader.getNextFile (), "content1.txt");

      fileStream = new ByteArrayOutputStream ();
      asicReader.writeFile (fileStream);
      assertEquals (fileStream.toString (), fileContent1);
    }

    {
      assertEquals (asicReader.getNextFile (), "content2.txt");

      fileStream = new ByteArrayOutputStream ();
      asicReader.writeFile (fileStream);
      assertEquals (fileStream.toString (), fileContent2);
    }

    assertNull (asicReader.getNextFile ());

    asicReader.close ();

    // Read container (zip)
    final ZipInputStream zipInputStream = new ZipInputStream (new ByteArrayInputStream (target.toByteArray ()));
    assertEquals (zipInputStream.getNextEntry ().getName (), "mimetype");
    assertEquals (zipInputStream.getNextEntry ().getName (), "content1.txt");
    assertEquals (zipInputStream.getNextEntry ().getName (), "META-INF/asicmanifest1.xml");
    assertTrue (AsicUtils.PATTERN_CADES_SIGNATURE.matcher (zipInputStream.getNextEntry ().getName ()).matches ());
    assertEquals (zipInputStream.getNextEntry ().getName (), "content2.txt");
    assertEquals (zipInputStream.getNextEntry ().getName (), "META-INF/asicmanifest2.xml");
    assertTrue (AsicUtils.PATTERN_CADES_SIGNATURE.matcher (zipInputStream.getNextEntry ().getName ()).matches ());
    assertEquals (zipInputStream.getNextEntry ().getName (), "META-INF/manifest.xml");
    assertNull (zipInputStream.getNextEntry ());
    zipInputStream.close ();
  }

  @Test
  public void combineWhereOnlyOneHasManifest () throws IOException
  {
    // Create first container
    final ByteArrayOutputStream source1 = new ByteArrayOutputStream ();
    asicWriterFactory.newContainer (source1)
                     .add (new ByteArrayInputStream (fileContent1.getBytes ()),
                           "content1.txt",
                           MimeType.forString ("text/plain"))
                     .sign (signatureHelper);

    // Create second container
    final ByteArrayOutputStream source2 = new ByteArrayOutputStream ();
    asicWriterFactory.newContainer (source2)
                     .add (new ByteArrayInputStream (fileContent2.getBytes ()),
                           "content2.txt",
                           MimeType.forString ("text/plain"))
                     .sign (signatureHelper);

    // Rewrite source2 to remove META-INF/manifest.xml
    final ByteArrayOutputStream source2simpler = new ByteArrayOutputStream ();
    final AsicInputStream source2input = new AsicInputStream (new ByteArrayInputStream (source2.toByteArray ()));
    final AsicOutputStream source2output = new AsicOutputStream (source2simpler);

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

    source2output.close ();
    source2input.close ();
    source2simpler.close ();

    // Combine containers
    final ByteArrayOutputStream target = new ByteArrayOutputStream ();
    AsicUtils.combine (target,
                       new ByteArrayInputStream (source1.toByteArray ()),
                       new ByteArrayInputStream (source2simpler.toByteArray ()));

    // Read container (zip)
    final ZipInputStream zipInputStream = new ZipInputStream (new ByteArrayInputStream (target.toByteArray ()));
    assertEquals (zipInputStream.getNextEntry ().getName (), "mimetype");
    assertEquals (zipInputStream.getNextEntry ().getName (), "content1.txt");
    assertEquals (zipInputStream.getNextEntry ().getName (), "META-INF/asicmanifest1.xml");
    assertTrue (AsicUtils.PATTERN_CADES_SIGNATURE.matcher (zipInputStream.getNextEntry ().getName ()).matches ());
    assertEquals (zipInputStream.getNextEntry ().getName (), "content2.txt");
    assertEquals (zipInputStream.getNextEntry ().getName (), "META-INF/asicmanifest2.xml");
    assertTrue (AsicUtils.PATTERN_CADES_SIGNATURE.matcher (zipInputStream.getNextEntry ().getName ()).matches ());
    assertNull (zipInputStream.getNextEntry ());
    zipInputStream.close ();
  }

  @Test
  public void simpleMultipleRootfiles () throws IOException
  {
    // Create first container
    final ByteArrayOutputStream source1 = new ByteArrayOutputStream ();
    asicWriterFactory.newContainer (source1)
                     .add (new ByteArrayInputStream (fileContent1.getBytes ()),
                           "content1.txt",
                           MimeType.forString ("text/plain"))
                     .setRootEntryName ("content1.txt")
                     .sign (signatureHelper);

    // Create second container
    final ByteArrayOutputStream source2 = new ByteArrayOutputStream ();
    asicWriterFactory.newContainer (source2)
                     .add (new ByteArrayInputStream (fileContent2.getBytes ()),
                           "content2.txt",
                           MimeType.forString ("text/plain"))
                     .setRootEntryName ("content2.txt")
                     .sign (signatureHelper);

    // Combine containers
    try
    {
      AsicUtils.combine (new ByteArrayOutputStream (),
                         new ByteArrayInputStream (source1.toByteArray ()),
                         new ByteArrayInputStream (source2.toByteArray ()));
      fail ("Exception expected.");
    }
    catch (final IllegalStateException e)
    {
      log.info (e.getMessage ());
    }
  }

  @Test
  public void simpleCombineXades () throws IOException
  {
    final AsicWriterFactory asicWriterFactory = AsicWriterFactory.newFactory (ESignatureMethod.XAdES);

    // Create first container
    final ByteArrayOutputStream source1 = new ByteArrayOutputStream ();
    asicWriterFactory.newContainer (source1)
                     .add (new ByteArrayInputStream (fileContent1.getBytes ()),
                           "content1.txt",
                           MimeType.forString ("text/plain"))
                     .sign (signatureHelper);

    // Create second container
    final ByteArrayOutputStream source2 = new ByteArrayOutputStream ();
    asicWriterFactory.newContainer (source2)
                     .add (new ByteArrayInputStream (fileContent2.getBytes ()),
                           "content2.txt",
                           MimeType.forString ("text/plain"))
                     .sign (signatureHelper);

    // Combine containers
    final ByteArrayOutputStream target = new ByteArrayOutputStream ();
    AsicUtils.combine (target,
                       new ByteArrayInputStream (source1.toByteArray ()),
                       new ByteArrayInputStream (source2.toByteArray ()));

    // Read container (asic)
    final IAsicReader asicReader = asicReaderFactory.open (new ByteArrayInputStream (target.toByteArray ()));

    ByteArrayOutputStream fileStream;
    {
      assertEquals (asicReader.getNextFile (), "content1.txt");

      fileStream = new ByteArrayOutputStream ();
      asicReader.writeFile (fileStream);
      assertEquals (fileStream.toString (), fileContent1);
    }

    {
      assertEquals (asicReader.getNextFile (), "content2.txt");

      fileStream = new ByteArrayOutputStream ();
      asicReader.writeFile (fileStream);
      assertEquals (fileStream.toString (), fileContent2);
    }

    assertNull (asicReader.getNextFile ());

    asicReader.close ();

    // Read container (zip)
    final ZipInputStream zipInputStream = new ZipInputStream (new ByteArrayInputStream (target.toByteArray ()));
    assertEquals (zipInputStream.getNextEntry ().getName (), "mimetype");
    assertEquals (zipInputStream.getNextEntry ().getName (), "content1.txt");
    assertEquals (zipInputStream.getNextEntry ().getName (), "META-INF/signatures1.xml");
    assertEquals (zipInputStream.getNextEntry ().getName (), "content2.txt");
    assertEquals (zipInputStream.getNextEntry ().getName (), "META-INF/signatures2.xml");
    assertEquals (zipInputStream.getNextEntry ().getName (), "META-INF/manifest.xml");
    assertNull (zipInputStream.getNextEntry ());
    zipInputStream.close ();
  }

  // Making Cobertura happy!
  @Test
  public void constructor ()
  {
    assertNotNull (new AsicUtils ());
  }
}
