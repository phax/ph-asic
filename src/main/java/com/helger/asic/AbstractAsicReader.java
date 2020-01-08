/**
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018-2020 Philip Helger (www.helger.com)
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
import javax.annotation.Nullable;
import javax.annotation.WillCloseWhenClosed;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.asic.jaxb.AsicReader;
import com.helger.asic.jaxb.asic.AsicManifest;
import com.helger.asic.jaxb.asic.Certificate;
import com.helger.asic.jaxb.opendocument.manifest.Manifest;
import com.helger.commons.base64.Base64;
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
  private static final String PREFIX_META_INF = "META-INF/";
  private static final Logger LOG = LoggerFactory.getLogger (AbstractAsicReader.class);

  private MessageDigest m_aMD;

  private AsicInputStream m_aZipInputStream;
  private ZipEntry m_aCurrentZipEntry;

  private final ManifestVerifier m_aManifestVerifier;
  private Manifest m_aManifest;

  // Initiated with 'true' as the first file should not do anything.
  private boolean m_bContentIsConsumed = true;

  /**
   * Used to hold signature or manifest for CAdES as they are not in the same
   * file.
   */
  private final ICommonsMap <String, byte []> m_aSigningContent = new CommonsHashMap <> ();

  protected AbstractAsicReader (@Nonnull final EMessageDigestAlgorithm eMDAlgo,
                                @Nonnull @WillCloseWhenClosed final InputStream aIS)
  {
    m_aManifestVerifier = new ManifestVerifier (eMDAlgo);

    try
    {
      m_aMD = MessageDigest.getInstance (eMDAlgo.getMessageDigestAlgorithm ());
      m_aMD.reset ();
    }
    catch (final NoSuchAlgorithmException ex)
    {
      throw new IllegalStateException ("Message Digest Algorithm '" +
                                       eMDAlgo.getMessageDigestAlgorithm () +
                                       "' is not supported",
                                       ex);
    }

    m_aZipInputStream = new AsicInputStream (aIS);
    // Comment in ZIP is stored in Central Directory in the end of the file.
  }

  private void _handleCadesSigning (final String sSigReference, final byte [] aObj, final boolean bIsSignature)
  {
    if (!m_aSigningContent.containsKey (sSigReference))
      m_aSigningContent.put (sSigReference, aObj);
    else
    {
      final byte [] aData = bIsSignature ? m_aSigningContent.get (sSigReference) : aObj;
      final byte [] aSignature = bIsSignature ? aObj : m_aSigningContent.get (sSigReference);

      // throws IllegalStateException if null
      final Certificate aCertificate = SignatureVerifier.validate (aData, aSignature);
      aCertificate.setCert (m_aCurrentZipEntry.getName ());
      m_aManifestVerifier.addCertificate (aCertificate);

      m_aSigningContent.remove (sSigReference);
    }
  }

  /**
   * Handles zip entries in the META-INF/ directory.
   *
   * @throws IOException
   */
  private void _handleMetadataEntry () throws IOException
  {
    final String sPathAndFilename = m_aCurrentZipEntry.getName ();

    // Read content in file
    try (final NonBlockingByteArrayOutputStream aBAOS = new NonBlockingByteArrayOutputStream ())
    {
      AsicUtils.copyStream (m_aZipInputStream, aBAOS);

      if (AsicUtils.PATTERN_CADES_MANIFEST.matcher (sPathAndFilename).matches ())
      {
        // Handling manifest in ASiC CAdES.
        final byte [] aContent = aBAOS.toByteArray ();
        final String sContent = new String (aContent, StandardCharsets.ISO_8859_1);
        final String sSigReference = CadesAsicManifest.extractAndVerify (sContent, m_aManifestVerifier);
        _handleCadesSigning (sSigReference, aContent, false);
      }
      else
        if (AsicUtils.PATTERN_CADES_SIGNATURE.matcher (sPathAndFilename).matches ())
        {
          // Handling signature in ASiC CAdES.
          _handleCadesSigning (sPathAndFilename, aBAOS.toByteArray (), true);
        }
        else
          if (AsicUtils.PATTERN_XADES_SIGNATURES.matcher (sPathAndFilename).matches ())
          {
            // Handling manifest in ASiC XAdES.
            final String sContent = aBAOS.getAsString (StandardCharsets.ISO_8859_1);
            XadesAsicManifest.extractAndVerify (sContent, m_aManifestVerifier);
          }
          else
            if (AsicUtils.PATTERN_OASIS_MANIFEST.matcher (sPathAndFilename).matches ())
            {
              // Read manifest.
              m_aManifest = AsicReader.oasisManifest ().read (aBAOS.getAsInputStream ());
            }
            else
            {
              throw new IllegalStateException ("ASiC contains unknown metadata file '" + sPathAndFilename + "'");
            }
    }
  }

  @Nullable
  public final String getNextFile () throws IOException
  {
    // Read file if the user didn't.
    if (!m_bContentIsConsumed)
      internalWriteFile (new NullOutputStream ());

    // Write digest to manifest
    if (m_aCurrentZipEntry != null)
    {
      final byte [] aDigest = m_aMD.digest ();
      if (LOG.isDebugEnabled ())
        LOG.debug ("Digest: " + Base64.encodeBytes (aDigest));
      m_aManifestVerifier.update (m_aCurrentZipEntry.getName (), aDigest, null);
    }

    while ((m_aCurrentZipEntry = m_aZipInputStream.getNextEntry ()) != null)
    {
      if (LOG.isDebugEnabled ())
        LOG.debug ("Found file: " + m_aCurrentZipEntry.getName ());

      // Files used for validation are not exposed
      if (m_aCurrentZipEntry.getName ().startsWith (PREFIX_META_INF))
      {
        _handleMetadataEntry ();
      }
      else
      {
        m_bContentIsConsumed = false;
        return m_aCurrentZipEntry.getName ();
      }
    }

    // Making sure signatures are used and all files are signed after reading
    // all content.

    // All files must be signed by minimum one manifest/signature.
    m_aManifestVerifier.verifyAllVerified ();

    // All CAdES signatures and manifest must be verified.
    if (m_aSigningContent.isNotEmpty ())
      throw new IllegalStateException ("Signatures not verified: " + m_aSigningContent.keySet ());

    // Return null when container is out of content to read.
    return null;
  }

  protected final void internalWriteFile (@Nonnull final OutputStream aOS) throws IOException
  {
    if (m_aCurrentZipEntry == null)
      throw new IllegalStateException ("No file to read.");

    // Calculate digest while reading file
    m_aMD.reset ();
    final DigestOutputStream aDOS = new DigestOutputStream (aOS, m_aMD);
    AsicUtils.copyStream (m_aZipInputStream, aDOS);

    m_aZipInputStream.closeEntry ();

    m_bContentIsConsumed = true;
  }

  @Nonnull
  protected InputStream internalInputStream ()
  {
    if (m_aCurrentZipEntry == null)
      throw new IllegalStateException ("No file to read.");

    // We must trust the user.
    m_bContentIsConsumed = true;

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
   * Property getter for the AsicManifest of the ASiC archive.
   *
   * @return value of property.
   */
  @Nonnull
  public final AsicManifest getAsicManifest ()
  {
    return m_aManifestVerifier.getAsicManifest ();
  }

  /**
   * Property getter for the OpenDocument manifest.
   *
   * @return value of property, <code>null</code> if document is not found in
   *         container.
   */
  @Nullable
  public final Manifest getOasisManifest ()
  {
    return m_aManifest;
  }
}
