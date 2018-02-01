package com.helger.asic;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.DigestOutputStream;
import java.util.zip.ZipEntry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractAsicWriter implements IAsicWriter
{
  public static final Logger logger = LoggerFactory.getLogger (AbstractAsicWriter.class);

  protected AsicOutputStream m_aAsicOutputStream;
  protected AbstractAsicManifest m_aAsicManifest;

  protected boolean m_bFinished = false;
  protected OutputStream m_aContainerOS;
  protected boolean m_bCloseStreamOnClose = false;

  protected OasisManifest m_aOasisManifest;

  /**
   * Prepares creation of a new container.
   *
   * @param outputStream
   *        Stream used to write container.
   * @param closeStreamOnClose
   * @param asicManifest
   */
  AbstractAsicWriter (final OutputStream outputStream,
                      final boolean closeStreamOnClose,
                      final AbstractAsicManifest asicManifest) throws IOException
  {
    // Keep original output stream
    this.m_aContainerOS = outputStream;
    this.m_bCloseStreamOnClose = closeStreamOnClose;

    // Initiate manifest
    this.m_aAsicManifest = asicManifest;

    // Initiate zip container
    m_aAsicOutputStream = new AsicOutputStream (outputStream);

    // Add mimetype to OASIS OpenDocument manifest
    m_aOasisManifest = new OasisManifest (MimeType.forString (AsicUtils.MIMETYPE_ASICE));
  }

  /** {@inheritDoc} */
  @Override
  public IAsicWriter add (final InputStream inputStream,
                          final String filename,
                          final MimeType mimeType) throws IOException
  {
    // Check status
    if (m_bFinished)
      throw new IllegalStateException ("Adding content to container after signing container is not supported.");

    if (filename.startsWith ("META-INF/"))
      throw new IllegalStateException ("Adding files to META-INF is not allowed.");

    // Creates new zip entry
    logger.debug ("Writing file '{}' to container", filename);
    m_aAsicOutputStream.putNextEntry (new ZipEntry (filename));

    // Prepare for calculation of message digest
    final DigestOutputStream zipOutputStreamWithDigest = new DigestOutputStream (m_aAsicOutputStream,
                                                                                 m_aAsicManifest.getMessageDigest ());

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

  /** {@inheritDoc} */
  @Override
  public IAsicWriter sign (final File keyStoreFile,
                           final String keyStorePassword,
                           final String keyPassword) throws IOException
  {
    return sign (keyStoreFile, keyStorePassword, null, keyPassword);
  }

  /** {@inheritDoc} */
  @Override
  public IAsicWriter sign (final File keyStoreFile,
                           final String keyStorePassword,
                           final String keyAlias,
                           final String keyPassword) throws IOException
  {
    return sign (new SignatureHelper (keyStoreFile, keyStorePassword, keyAlias, keyPassword));
  }

  /** {@inheritDoc} */
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

    m_aAsicOutputStream.writeZipEntry ("META-INF/manifest.xml", m_aOasisManifest.toBytes ());

    // Close container
    try
    {
      m_aAsicOutputStream.finish ();
      m_aAsicOutputStream.close ();
    }
    catch (final IOException e)
    {
      throw new IllegalStateException (String.format ("Unable to finish the container: %s", e.getMessage ()), e);
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
        throw new IllegalStateException (String.format ("Unable to close file: %s", e.getMessage ()), e);
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
