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

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import javax.annotation.Nonnull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.commons.ValueEnforcer;

/**
 * Creates AsicWriter instances according to the supplied parameters.
 */
public class AsicWriterFactory
{
  private static final Logger logger = LoggerFactory.getLogger (AsicWriterFactory.class);

  /**
   * Creates an AsicWriterFactory, which utilises the default signature method,
   * which is currently CAdES.
   *
   * @return instantiated AsicWriterFactory
   */
  @Nonnull
  public static AsicWriterFactory newFactory ()
  {
    return newFactory (ESignatureMethod.CAdES);
  }

  /**
   * Creates an AsicWriterFactory using the supplied signature method.
   *
   * @param signatureMethod
   *        the signature method to be used.
   * @return instantiated AsicWriterFactory
   * @see ESignatureMethod
   */
  @Nonnull
  public static AsicWriterFactory newFactory (@Nonnull final ESignatureMethod signatureMethod)
  {
    return new AsicWriterFactory (signatureMethod);
  }

  private final ESignatureMethod m_eSM;

  protected AsicWriterFactory (@Nonnull final ESignatureMethod eSM)
  {
    ValueEnforcer.notNull (eSM, "SM");
    m_eSM = eSM;
  }

  /**
   * Factory method creating a new AsicWriter, which will create an ASiC archive
   * in the supplied directory with the supplied file name
   *
   * @param outputDir
   *        the directory in which the archive will be created.
   * @param filename
   *        the name of the archive.
   * @return an instance of AsicWriter
   * @throws IOException
   *         on IO error
   */
  @Nonnull
  public IAsicWriter newContainer (final File outputDir, final String filename) throws IOException
  {
    return newContainer (new File (outputDir, filename));
  }

  /**
   * Creates a new AsicWriter, which will create an ASiC archive in the supplied
   * file.
   *
   * @param file
   *        the file reference to the archive.
   * @return an instance of AsicWriter
   * @throws IOException
   *         on IO error
   */
  @Nonnull
  public IAsicWriter newContainer (final File file) throws IOException
  {
    return newContainer (file.toPath ());
  }

  @Nonnull
  public IAsicWriter newContainer (final Path path) throws IOException
  {
    // Conformance to ETSI TS 102 918, 6.2.1 1)
    if (!AsicUtils.PATTERN_EXTENSION_ASICE.matcher (path.toString ()).matches ())
      logger.warn ("ASiC-E files should use \"asice\" as file extension.");

    return newContainer (Files.newOutputStream (path), true);
  }

  /**
   * Creates a new AsicWriter, which will write the container contents to the
   * supplied output stream.
   *
   * @param outputStream
   *        stream into which the archive will be written.
   * @return an instance of AsicWriter
   * @throws IOException
   *         on IO error
   */
  @Nonnull
  public IAsicWriter newContainer (final OutputStream outputStream) throws IOException
  {
    return newContainer (outputStream, false);
  }

  @Nonnull
  public IAsicWriter newContainer (final OutputStream outputStream, final boolean closeStreamOnClose) throws IOException
  {
    switch (m_eSM)
    {
      case CAdES:
        return new CadesAsicWriter (m_eSM, outputStream, closeStreamOnClose);
      case XAdES:
        return new XadesAsicWriter (m_eSM, outputStream, closeStreamOnClose);
      default:
        throw new IllegalStateException ("Not implemented: " + m_eSM);
    }
  }
}
