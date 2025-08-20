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
package com.helger.asic;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.DigestOutputStream;
import java.util.zip.ZipEntry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.annotation.OverridingMethodsMustInvokeSuper;
import com.helger.annotation.concurrent.NotThreadSafe;
import com.helger.base.enforce.ValueEnforcer;
import com.helger.mime.IMimeType;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

/**
 * Abstract implementation of {@link IAsicWriter}.
 */
@NotThreadSafe
public abstract class AbstractAsicWriter implements IAsicWriter
{
  private static final Logger LOGGER = LoggerFactory.getLogger (AbstractAsicWriter.class);

  protected boolean m_bFinished = false;
  protected final OutputStream m_aContainerOS;
  protected final AsicOutputStream m_aAsicOutputStream;
  protected final boolean m_bCloseStreamOnSign;
  protected final AbstractAsicManifest m_aAsicManifest;
  private final OasisManifest m_aOasisManifest;

  /**
   * Prepares creation of a new container.
   *
   * @param aOS
   *        Stream used to write container.
   * @param bCloseStreamOnSign
   *        close output stream after signing
   * @param aAsicManifest
   *        The asic manifest to use
   * @param bWriteOasisManifest
   *        <code>true</code> if the OASIS OpenDocument Manifest XML should also
   *        be created.
   * @throws IOException
   *         in case of IO error
   */
  protected AbstractAsicWriter (@Nonnull final OutputStream aOS,
                                final boolean bCloseStreamOnSign,
                                @Nonnull final AbstractAsicManifest aAsicManifest,
                                final boolean bWriteOasisManifest) throws IOException
  {
    // Keep original output stream
    m_aContainerOS = aOS;
    m_bCloseStreamOnSign = bCloseStreamOnSign;

    // Initiate manifest
    m_aAsicManifest = aAsicManifest;

    // Initiate zip container
    m_aAsicOutputStream = new AsicOutputStream (aOS);

    // Add mimetype to OASIS OpenDocument manifest
    m_aOasisManifest = bWriteOasisManifest ? new OasisManifest (AsicUtils.MIMETYPE_ASICE) : null;
  }

  @Nonnull
  public IAsicWriter add (@Nonnull final InputStream aIS,
                          @Nonnull final String sFilename,
                          @Nonnull final IMimeType aMimeType) throws IOException, IllegalStateException
  {
    ValueEnforcer.notNull (aIS, "IS");
    ValueEnforcer.notNull (sFilename, "Filename");
    ValueEnforcer.notNull (aMimeType, "MimeType");

    // Check status
    if (m_bFinished)
      throw new IllegalStateException ("Adding content to container after signing container is not supported.");

    if (sFilename.startsWith ("META-INF/"))
      throw new IllegalStateException ("Adding files to META-INF is not allowed.");

    // Creates new zip entry
    if (LOGGER.isDebugEnabled ())
      LOGGER.debug ("Writing file '" + sFilename + "' to container");
    m_aAsicOutputStream.putNextEntry (new ZipEntry (sFilename));

    // Prepare for calculation of message digest
    final DigestOutputStream aDigestOS = new DigestOutputStream (m_aAsicOutputStream,
                                                                 m_aAsicManifest.getNewMessageDigest ());

    // Copy inputStream to zip output stream
    AsicUtils.copyStream (aIS, aDigestOS);

    // Closes the zip entry
    m_aAsicOutputStream.closeEntry ();

    // Adds contents of input stream to manifest which will be signed and
    // written once all data objects have been added
    m_aAsicManifest.add (sFilename, aMimeType);

    // Add record of file to OASIS OpenDocument Manifest
    if (m_aOasisManifest != null)
      m_aOasisManifest.add (sFilename, aMimeType);

    return this;
  }

  /**
   * Creating the signature and writing it into the archive is delegated to the
   * actual implementation
   *
   * @param aSH
   *        Signature helper for signing details
   * @throws IOException
   *         in case of IO error
   */
  protected abstract void performSign (@Nonnull SignatureHelper aSH) throws IOException;

  @Nonnull
  public IAsicWriter sign (@Nonnull final SignatureHelper aSH) throws IOException
  {
    // You may only sign once
    if (m_bFinished)
      throw new IllegalStateException ("Adding content to container after signing container is not supported.");

    // Flip status to ensure nobody is allowed to sign more than once.
    m_bFinished = true;

    // Delegates the actual signature creation to the signature helper
    performSign (aSH);

    if (m_aOasisManifest != null)
      m_aAsicOutputStream.writeZipEntry ("META-INF/" + AsicUtils.OASIS_MANIFEST_BASENAME + ".xml",
                                         m_aOasisManifest.getAsBytes ());

    // Close container
    try
    {
      m_aAsicOutputStream.finish ();
      m_aAsicOutputStream.close ();
    }
    catch (final IOException e)
    {
      throw new IllegalStateException ("Unable to finish the container", e);
    }

    if (m_bCloseStreamOnSign)
    {
      try
      {
        m_aContainerOS.flush ();
        m_aContainerOS.close ();
      }
      catch (final IOException e)
      {
        throw new IllegalStateException ("Unable to close file", e);
      }
    }

    return this;
  }

  // Cannot be final
  @Nonnull
  @OverridingMethodsMustInvokeSuper
  public AbstractAsicManifest getAsicManifest ()
  {
    return m_aAsicManifest;
  }

  @Nullable
  protected final OasisManifest getOasisManifest ()
  {
    return m_aOasisManifest;
  }
}
