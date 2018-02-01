package com.helger.asic.extras;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.bouncycastle.cms.CMSAlgorithm;
import org.junit.Ignore;
import org.junit.Test;

import com.helger.asic.AsicReaderFactory;
import com.helger.asic.AsicWriterFactory;
import com.helger.asic.IAsicReader;
import com.helger.asic.IAsicWriter;
import com.helger.asic.MimeType;
import com.helger.asic.SignatureHelper;

public final class CmsEncryptedAsicTest
{
  @Test
  public void simple () throws Exception
  {

    // WRITE TO ASIC
    final KeyStore keyStore = loadKeyStore ();

    // Fetching certificate
    final X509Certificate certificate = (X509Certificate) keyStore.getCertificate ("selfsigned");

    // Store result in ByteArrayOutputStream
    final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream ();

    // Create a new ASiC archive
    final IAsicWriter asicWriter = AsicWriterFactory.newFactory ().newContainer (byteArrayOutputStream);
    // Encapsulate ASiC archive to enable writing encrypted content
    final CmsEncryptedAsicWriter writer = new CmsEncryptedAsicWriter (asicWriter, certificate, CMSAlgorithm.AES128_GCM);
    writer.add (getClass ().getResourceAsStream ("/image.bmp"), "simple.bmp", MimeType.forString ("image/bmp"));
    writer.addEncrypted (getClass ().getResourceAsStream ("/image.bmp"),
                         "encrypted.bmp",
                         MimeType.forString ("image/bmp"));
    writer.addEncrypted (Paths.get (getClass ().getResource ("/image.bmp").toURI ()),
                         "encrypted2.bmp",
                         MimeType.forString ("image/bmp"));
    writer.addEncrypted (Paths.get (getClass ().getResource ("/image.bmp").toURI ()).toFile (), "encrypted3.xml");
    writer.setRootEntryName ("encrypted.bmp");
    writer.sign (new SignatureHelper (getClass ().getResourceAsStream ("/keystore.jks"),
                                      "changeit",
                                      "selfsigned",
                                      "changeit"));
    // ByteArrayOutputStream now contains a signed ASiC archive containing one
    // encrypted file

    // READ FROM ASIC

    // Fetch private key from keystore
    final PrivateKey privateKey = (PrivateKey) keyStore.getKey ("selfsigned", "changeit".toCharArray ());

    // Open content of ByteArrayOutputStream for reading
    try (final IAsicReader asicReader = AsicReaderFactory.newFactory ()
                                                         .open (new ByteArrayInputStream (byteArrayOutputStream.toByteArray ())))
    {
      // Encapsulate ASiC archive to enable reading encrypted content
      try (final CmsEncryptedAsicReader reader = new CmsEncryptedAsicReader (asicReader, privateKey))
      {
        // Read plain file
        assertEquals (reader.getNextFile (), "simple.bmp");
        final ByteArrayOutputStream file1 = new ByteArrayOutputStream ();
        reader.writeFile (file1);

        // Read encrypted file
        assertEquals (reader.getNextFile (), "encrypted.bmp");
        final ByteArrayOutputStream file2 = new ByteArrayOutputStream ();
        reader.writeFile (file2);

        // Read encrypted file 2
        assertEquals (reader.getNextFile (), "encrypted2.bmp");
        final ByteArrayOutputStream file3 = new ByteArrayOutputStream ();
        reader.writeFile (file3);

        // Read encrypted file 3
        assertEquals (reader.getNextFile (), "encrypted3.xml");
        final ByteArrayOutputStream file4 = new ByteArrayOutputStream ();
        reader.writeFile (file4);

        // Verify both files contain the same data
        assertArrayEquals (file2.toByteArray (), file1.toByteArray ());

        // Verify no more files are found
        assertNull (reader.getNextFile ());

        // Verify certificate used for signing of ASiC is the same as the one
        // used
        // for signing
        assertArrayEquals (reader.getAsicManifest ().getCertificate ().get (0).getCertificate (),
                           certificate.getEncoded ());

        assertEquals (reader.getAsicManifest ().getRootfile (), "encrypted.bmp");
      }
    }

    // Writes the ASiC file to temporary directory
    final File sample = File.createTempFile ("sample", ".asice");
    try (FileOutputStream fileOutputStream = new FileOutputStream (sample))
    {
      fileOutputStream.write (byteArrayOutputStream.toByteArray ());
    }
    System.out.println ("Wrote sample ASiC to " + sample);

  }

  private KeyStore loadKeyStore () throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException
  {
    // Read JKS
    final KeyStore keyStore = KeyStore.getInstance ("JKS");
    keyStore.load (getClass ().getResourceAsStream ("/keystore.jks"), "changeit".toCharArray ());
    return keyStore;
  }

  @Test
  @Ignore
  public void createSampleForBits () throws Exception
  {

    // Obtains the keystore
    final KeyStore keyStore = loadKeyStore ();

    // Fetching certificate
    final X509Certificate certificate = (X509Certificate) keyStore.getCertificate ("selfsigned");

    // Store result in outputfile
    final File sample = File.createTempFile ("sample-bits", ".asice");
    try (FileOutputStream fileOutputStream = new FileOutputStream (sample))
    {

      // Create a new ASiC archive
      final IAsicWriter asicWriter = AsicWriterFactory.newFactory ().newContainer (fileOutputStream);
      // Encapsulate ASiC archive to enable writing encrypted content
      final CmsEncryptedAsicWriter writer = new CmsEncryptedAsicWriter (asicWriter, certificate);

      // Adds the SBDH
      writer.add (getClass ().getResourceAsStream ("/sample-sbdh.xml"),
                  "sbdh.xml",
                  MimeType.forString ("application/xml"));

      // Adds the plain text sample document
      writer.add (getClass ().getResourceAsStream ("/bii-trns081.xml"),
                  "sample.xml",
                  MimeType.forString ("application/xml"));

      // Adds the encrypted version of the sample document
      writer.addEncrypted (getClass ().getResourceAsStream ("/bii-trns081.xml"),
                           "sample.xml",
                           MimeType.forString ("application/xml"));

      // Indicates which document is the root entry (to be read first)
      writer.setRootEntryName ("sample.xml");

      // Signs the archive
      final SignatureHelper signatureHelper = new SignatureHelper (getClass ().getResourceAsStream ("/keystore.jks"),
                                                                   "changeit",
                                                                   "selfsigned",
                                                                   "changeit");
      writer.sign (signatureHelper);

    }

    System.out.println ("Wrote sample ASiC to " + sample);
  }

}
