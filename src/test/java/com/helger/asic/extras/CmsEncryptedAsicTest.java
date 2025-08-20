/*
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018-2025 Philip Helger (www.helger.com)
 * philip[at]helger[dot]com
 *
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed
 * with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/
 */
package com.helger.asic.extras;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.bouncycastle.cms.CMSAlgorithm;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.asic.AsicReaderFactory;
import com.helger.asic.AsicWriterFactory;
import com.helger.asic.ESignatureMethod;
import com.helger.asic.IAsicReader;
import com.helger.asic.IAsicWriter;
import com.helger.asic.TestUtil;
import com.helger.base.io.nonblocking.NonBlockingByteArrayOutputStream;
import com.helger.io.resource.ClassPathResource;
import com.helger.mime.CMimeType;

public final class CmsEncryptedAsicTest
{
  private static final Logger LOGGER = LoggerFactory.getLogger (CmsEncryptedAsicTest.class);

  @Test
  public void simple () throws Exception
  {
    // WRITE TO ASIC
    final KeyStore keyStore = loadKeyStore ();

    // Fetching certificate
    final X509Certificate certificate = (X509Certificate) keyStore.getCertificate ("selfsigned");

    // Store result in NonBlockingByteArrayOutputStream
    try (final NonBlockingByteArrayOutputStream byteArrayOutputStream = new NonBlockingByteArrayOutputStream ())
    {

      // Create a new ASiC archive
      final IAsicWriter asicWriter = AsicWriterFactory.newFactory (ESignatureMethod.CAdES)
                                                      .newContainer (byteArrayOutputStream);
      // Encapsulate ASiC archive to enable writing encrypted content
      final CmsEncryptedAsicWriter writer = new CmsEncryptedAsicWriter (asicWriter,
                                                                        certificate,
                                                                        CMSAlgorithm.AES128_GCM);
      writer.add (ClassPathResource.getInputStream ("external/asic/image.bmp"), "simple.bmp", CMimeType.IMAGE_BMP);
      writer.addEncrypted (ClassPathResource.getInputStream ("external/asic/image.bmp"),
                           "encrypted.bmp",
                           CMimeType.IMAGE_BMP);
      writer.addEncrypted (ClassPathResource.getAsFile ("external/asic/image.bmp"),
                           "encrypted2.bmp",
                           CMimeType.IMAGE_BMP);
      writer.addEncrypted (ClassPathResource.getAsFile ("external/asic/image.bmp"), "encrypted3.xml");
      writer.setRootEntryName ("encrypted.bmp");
      writer.sign (TestUtil.createSH ());
      // NonBlockingByteArrayOutputStream now contains a signed ASiC archive
      // containing one
      // encrypted file

      // READ FROM ASIC

      // Fetch private key from keystore
      final PrivateKey privateKey = (PrivateKey) keyStore.getKey ("selfsigned", "changeit".toCharArray ());

      // Open content of NonBlockingByteArrayOutputStream for reading
      try (final IAsicReader asicReader = AsicReaderFactory.newFactory ()
                                                           .open (byteArrayOutputStream.getAsInputStream ()))
      {
        // Encapsulate ASiC archive to enable reading encrypted content
        try (final CmsEncryptedAsicReader reader = new CmsEncryptedAsicReader (asicReader, privateKey))
        {
          // Read plain file
          assertEquals (reader.getNextFile (), "simple.bmp");
          final NonBlockingByteArrayOutputStream file1 = new NonBlockingByteArrayOutputStream ();
          reader.writeFile (file1);

          // Read encrypted file
          assertEquals (reader.getNextFile (), "encrypted.bmp");
          final NonBlockingByteArrayOutputStream file2 = new NonBlockingByteArrayOutputStream ();
          reader.writeFile (file2);

          // Read encrypted file 2
          assertEquals (reader.getNextFile (), "encrypted2.bmp");
          final NonBlockingByteArrayOutputStream file3 = new NonBlockingByteArrayOutputStream ();
          reader.writeFile (file3);

          // Read encrypted file 3
          assertEquals (reader.getNextFile (), "encrypted3.xml");
          final NonBlockingByteArrayOutputStream file4 = new NonBlockingByteArrayOutputStream ();
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
      final File aSampleFile = File.createTempFile ("sample", ".asice");
      try (final FileOutputStream fileOutputStream = new FileOutputStream (aSampleFile))
      {
        fileOutputStream.write (byteArrayOutputStream.toByteArray ());
      }
      LOGGER.info ("Wrote sample ASiC to " + aSampleFile);
    }
  }

  private KeyStore loadKeyStore () throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException
  {
    // Read JKS
    final KeyStore keyStore = KeyStore.getInstance ("JKS");
    keyStore.load (ClassPathResource.getInputStream ("external/asic/keystore.jks"), "changeit".toCharArray ());
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
    try (final FileOutputStream fileOutputStream = new FileOutputStream (sample))
    {
      // Create a new ASiC archive
      final IAsicWriter asicWriter = AsicWriterFactory.newFactory (ESignatureMethod.CAdES)
                                                      .newContainer (fileOutputStream);
      // Encapsulate ASiC archive to enable writing encrypted content
      final CmsEncryptedAsicWriter writer = new CmsEncryptedAsicWriter (asicWriter, certificate);

      // Adds the SBDH
      writer.add (ClassPathResource.getInputStream ("external/asic/sample-sbdh.xml"),
                  "sbdh.xml",
                  CMimeType.APPLICATION_XML);

      // Adds the plain text sample document
      writer.add (ClassPathResource.getInputStream ("external/asic/bii-trns081.xml"),
                  "sample.xml",
                  CMimeType.APPLICATION_XML);

      // Adds the encrypted version of the sample document
      writer.addEncrypted (ClassPathResource.getInputStream ("external/asic/bii-trns081.xml"),
                           "sample.xml",
                           CMimeType.APPLICATION_XML);

      // Indicates which document is the root entry (to be read first)
      writer.setRootEntryName ("sample.xml");

      // Signs the archive
      writer.sign (TestUtil.createSH ());
    }

    LOGGER.info ("Wrote sample ASiC to " + sample);
  }

}
