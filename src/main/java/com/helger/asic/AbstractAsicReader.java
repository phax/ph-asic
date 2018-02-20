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

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.DigestInputStream;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.zip.ZipEntry;

import javax.annotation.Nonnull;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.asic.jaxb.AsicReader;
import com.helger.asic.jaxb.asic.AsicManifest;
import com.helger.asic.jaxb.asic.Certificate;
import com.helger.asic.jaxb.opendocument.manifest.Manifest;
import com.helger.commons.collection.impl.CommonsHashMap;
import com.helger.commons.collection.impl.ICommonsMap;
import com.helger.commons.io.stream.NonBlockingByteArrayOutputStream;
import com.helger.commons.io.stream.NullOutputStream;
import com.helger.commons.io.stream.StreamHelper;

/**
 * Skeleton implementation of ASiC archive reader.
 *
 * @author Erlend Klakegg Bergheim
 */
public abstract class AbstractAsicReader implements Closeable
{
  private static final Logger LOG = LoggerFactory.getLogger (AbstractAsicReader.class);

  private MessageDigest m_aMD;

  private AsicInputStream m_aZipInputStream;
  private ZipEntry m_aCurrentZipEntry;

  private final ManifestVerifier m_aManifestVerifier;
  private Manifest m_aManifest;

  // Initiated with 'true' as the first file should not do anything.
  private boolean m_bContentIsWritten = true;

  /**
   * Used to hold signature or manifest for CAdES as they are not in the same
   * file.
   */
  private final ICommonsMap <String, byte []> m_aSigningContent = new CommonsHashMap <> ();

  protected AbstractAsicReader (@Nonnull final EMessageDigestAlgorithm eMDAlgo, @Nonnull final InputStream inputStream)
  {
    m_aManifestVerifier = new ManifestVerifier (eMDAlgo);

    try
    {
      m_aMD = MessageDigest.getInstance (eMDAlgo.getAlgorithm ());
      m_aMD.reset ();
    }
    catch (final NoSuchAlgorithmException e)
    {
      throw new IllegalStateException ("Algorithm " + eMDAlgo.getAlgorithm () + " not supported", e);
    }

    m_aZipInputStream = new AsicInputStream (inputStream);
    // Comment in ZIP is stored in Central Directory in the end of the file.
  }

  public final String getNextFile () throws IOException
  {
    // Read file if the user didn't.
    if (!m_bContentIsWritten)
      internalWriteFile (new NullOutputStream ());

    // Write digest to manifest
    if (m_aCurrentZipEntry != null)
    {
      final byte [] digest = m_aMD.digest ();
      if (LOG.isDebugEnabled ())
        LOG.debug ("Digest: " + Base64.encode (digest));
      m_aManifestVerifier.update (m_aCurrentZipEntry.getName (), digest, null);
    }

    while ((m_aCurrentZipEntry = m_aZipInputStream.getNextEntry ()) != null)
    {
      if (LOG.isDebugEnabled ())
        LOG.debug ("Found file: " + m_aCurrentZipEntry.getName ());

      // Files used for validation are not exposed
      if (m_aCurrentZipEntry.getName ().startsWith ("META-INF/"))
        _handleMetadataEntry ();
      else
      {
        m_bContentIsWritten = false;
        return m_aCurrentZipEntry.getName ();
      }
    }

    // Making sure signatures are used and all files are signed after reading
    // all content.

    // All files must be signed by minimum one manifest/signature.
    m_aManifestVerifier.verifyAllVerified ();

    // All CAdES signatures and manifest must be verified.
    if (m_aSigningContent.size () > 0)
      throw new IllegalStateException ("Signature not verified: " + m_aSigningContent.keySet ().iterator ().next ());

    // Return null when container is out of content to read.
    return null;
  }

  protected final void internalWriteFile (@Nonnull final OutputStream outputStream) throws IOException
  {
    if (m_aCurrentZipEntry == null)
      throw new IllegalStateException ("No file to read.");

    // Calculate digest while reading file
    m_aMD.reset ();
    final DigestOutputStream digestOutputStream = new DigestOutputStream (outputStream, m_aMD);
    AsicUtils.copyStream (m_aZipInputStream, digestOutputStream);

    m_aZipInputStream.closeEntry ();

    m_bContentIsWritten = true;
  }

  @Nonnull
  protected InputStream internalInputStream ()
  {
    if (m_aCurrentZipEntry == null)
      throw new IllegalStateException ("No file to read.");

    // We must trust the user.
    m_bContentIsWritten = true;

    m_aMD.reset ();
    return new DigestInputStream (m_aZipInputStream, m_aMD);
  }

  @Override
  public final void close () throws IOException
  {
    StreamHelper.close (m_aZipInputStream);
    m_aZipInputStream = null;
  }

  /**
   * Handles zip entries in the META-INF/ directory.
   *
   * @throws IOException
   */
  private void _handleMetadataEntry () throws IOException
  {
    // Extracts everything after META-INF/
    final String filename = m_aCurrentZipEntry.getName ().substring (9).toLowerCase ();

    // Read content in file
    final NonBlockingByteArrayOutputStream contentsOfStream = new NonBlockingByteArrayOutputStream ();
    AsicUtils.copyStream (m_aZipInputStream, contentsOfStream);

    if (AsicUtils.PATTERN_CADES_MANIFEST.matcher (m_aCurrentZipEntry.getName ()).matches ())
    {
      // Handling manifest in ASiC CAdES.
      final byte [] aContent = contentsOfStream.toByteArray ();
      final String sContent = new String (aContent, StandardCharsets.ISO_8859_1);
      final String sigReference = CadesAsicManifest.extractAndVerify (sContent, m_aManifestVerifier);
      _handleCadesSigning (sigReference, aContent, false);
    }
    else
      if (AsicUtils.PATTERN_XADES_SIGNATURES.matcher (m_aCurrentZipEntry.getName ()).matches ())
      {
        // Handling manifest in ASiC XAdES.
        final String sContent = contentsOfStream.getAsString (StandardCharsets.ISO_8859_1);
        XadesAsicManifest.extractAndVerify (sContent, m_aManifestVerifier);
      }
      else
        if (AsicUtils.PATTERN_CADES_SIGNATURE.matcher (m_aCurrentZipEntry.getName ()).matches ())
        {
          // Handling signature in ASiC CAdES.
          _handleCadesSigning (m_aCurrentZipEntry.getName (), contentsOfStream.toByteArray (), true);
        }
        else
          if (filename.equals ("manifest.xml"))
          {
            // Read manifest.
            m_aManifest = AsicReader.oasisManifest ().read (contentsOfStream.getAsInputStream ());
          }
          else
          {
            throw new IllegalStateException ("Contains unknown metadata file: " + m_aCurrentZipEntry.getName ());
          }
  }

  private void _handleCadesSigning (final String sigReference, final byte [] o, final boolean bIsSignature)
  {
    if (!m_aSigningContent.containsKey (sigReference))
      m_aSigningContent.put (sigReference, o);
    else
    {
      final byte [] data = bIsSignature ? m_aSigningContent.get (sigReference) : o;
      final byte [] sign = bIsSignature ? o : m_aSigningContent.get (sigReference);

      final Certificate certificate = SignatureVerifier.validate (data, sign);
      certificate.setCert (m_aCurrentZipEntry.getName ());
      m_aManifestVerifier.addCertificate (certificate);

      m_aSigningContent.remove (sigReference);
    }
  }

  /**
   * Property getter for the AsicManifest of the ASiC archive.
   *
   * @return value of property.
   */
  public AsicManifest getAsicManifest ()
  {
    return m_aManifestVerifier.getAsicManifest ();
  }

  /**
   * Property getter for the OpenDocument manifest.
   *
   * @return value of property, null if document is not found in container.
   */
  public Manifest getOasisManifest ()
  {
    return m_aManifest;
  }
}
