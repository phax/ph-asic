/**
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018-2019 Philip Helger (www.helger.com)
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
  private static final Logger LOG = LoggerFactory.getLogger (AsicWriterFactory.class);

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
   * @param aOutputDir
   *        the directory in which the archive will be created.
   * @param sFilename
   *        the name of the archive.
   * @return an instance of AsicWriter
   * @throws IOException
   *         on IO error
   */
  @Nonnull
  public IAsicWriter newContainer (@Nonnull final File aOutputDir, @Nonnull final String sFilename) throws IOException
  {
    return newContainer (new File (aOutputDir, sFilename));
  }

  /**
   * Creates a new AsicWriter, which will create an ASiC archive in the supplied
   * file.
   *
   * @param aFile
   *        the file reference to the archive.
   * @return an instance of AsicWriter
   * @throws IOException
   *         on IO error
   */
  @Nonnull
  public IAsicWriter newContainer (@Nonnull final File aFile) throws IOException
  {
    return newContainer (aFile.toPath ());
  }

  @Nonnull
  public IAsicWriter newContainer (@Nonnull final Path aPath) throws IOException
  {
    // Conformance to ETSI TS 102 918, 6.2.1 1)
    if (!AsicUtils.PATTERN_EXTENSION_ASICE.matcher (aPath.toString ()).matches ())
      LOG.warn ("ASiC-E files should use \"asice\" as file extension.");

    return newContainer (Files.newOutputStream (aPath), true);
  }

  /**
   * Creates a new AsicWriter, which will write the container contents to the
   * supplied output stream.
   *
   * @param aOS
   *        stream into which the archive will be written.
   * @return an instance of AsicWriter
   * @throws IOException
   *         on IO error
   */
  @Nonnull
  public IAsicWriter newContainer (@Nonnull final OutputStream aOS) throws IOException
  {
    return newContainer (aOS, false);
  }

  @Nonnull
  public IAsicWriter newContainer (@Nonnull final OutputStream aOS,
                                   final boolean bCloseStreamOnSign) throws IOException
  {
    switch (m_eSM)
    {
      case CAdES:
        return new CadesAsicWriter (m_eSM, aOS, bCloseStreamOnSign);
      case XAdES:
        return new XadesAsicWriter (m_eSM, aOS, bCloseStreamOnSign);
      default:
        throw new IllegalStateException ("Not implemented: " + m_eSM);
    }
  }
}
