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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.DigestOutputStream;
import java.util.zip.ZipEntry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.commons.mime.IMimeType;

public abstract class AbstractAsicWriter implements IAsicWriter
{
  private static final Logger logger = LoggerFactory.getLogger (AbstractAsicWriter.class);

  protected AsicOutputStream m_aAsicOutputStream;
  protected AbstractAsicManifest m_aAsicManifest;

  protected boolean m_bFinished = false;
  protected OutputStream m_aContainerOS;
  protected boolean m_bCloseStreamOnClose = false;

  protected OasisManifest m_aOasisManifest;

  /**
   * Prepares creation of a new container.
   *
   * @param aOS
   *        Stream used to write container.
   * @param bCloseStreamOnClose
   * @param aAsicManifest
   */
  AbstractAsicWriter (final OutputStream aOS,
                      final boolean bCloseStreamOnClose,
                      final AbstractAsicManifest aAsicManifest) throws IOException
  {
    // Keep original output stream
    m_aContainerOS = aOS;
    m_bCloseStreamOnClose = bCloseStreamOnClose;

    // Initiate manifest
    m_aAsicManifest = aAsicManifest;

    // Initiate zip container
    m_aAsicOutputStream = new AsicOutputStream (aOS);

    // Add mimetype to OASIS OpenDocument manifest
    m_aOasisManifest = new OasisManifest (AsicUtils.MIMETYPE_ASICE);
  }

  @Override
  public IAsicWriter add (final InputStream inputStream,
                          final String filename,
                          final IMimeType mimeType) throws IOException
  {
    // Check status
    if (m_bFinished)
      throw new IllegalStateException ("Adding content to container after signing container is not supported.");

    if (filename.startsWith ("META-INF/"))
      throw new IllegalStateException ("Adding files to META-INF is not allowed.");

    // Creates new zip entry
    if (logger.isDebugEnabled ())
      logger.debug ("Writing file '" + filename + "' to container");
    m_aAsicOutputStream.putNextEntry (new ZipEntry (filename));

    // Prepare for calculation of message digest
    final DigestOutputStream zipOutputStreamWithDigest = new DigestOutputStream (m_aAsicOutputStream,
                                                                                 m_aAsicManifest.getNewMessageDigest ());

    // Copy inputStream to zip output stream
    AsicUtils.copyStream (inputStream, zipOutputStreamWithDigest);

    // Closes the zip entry
    m_aAsicOutputStream.closeEntry ();

    // Adds contents of input stream to manifest which will be signed and
    // written once all data objects have been added
    m_aAsicManifest.add (filename, mimeType);

    // Add record of file to OASIS OpenDocument Manifest
    m_aOasisManifest.add (filename, mimeType);

    return this;
  }

  @Override
  public IAsicWriter sign (final SignatureHelper signatureHelper) throws IOException
  {
    // You may only sign once
    if (m_bFinished)
      throw new IllegalStateException ("Adding content to container after signing container is not supported.");

    // Flip status to ensure nobody is allowed to sign more than once.
    m_bFinished = true;

    // Delegates the actual signature creation to the signature helper
    performSign (signatureHelper);

    m_aAsicOutputStream.writeZipEntry ("META-INF/manifest.xml", m_aOasisManifest.getAsBytes ());

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

    if (m_bCloseStreamOnClose)
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

  /**
   * Creating the signature and writing it into the archive is delegated to the
   * actual implementation
   */
  protected abstract void performSign (SignatureHelper signatureHelper) throws IOException;

  public AbstractAsicManifest getAsicManifest ()
  {
    return m_aAsicManifest;
  }
}
