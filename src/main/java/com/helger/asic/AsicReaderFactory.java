/*
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018-2026 Philip Helger (www.helger.com)
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
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import org.jspecify.annotations.NonNull;

import com.helger.annotation.style.ReturnsMutableCopy;
import com.helger.base.enforce.ValueEnforcer;
import com.helger.io.zip.ZipWalkerSettings;

public class AsicReaderFactory
{
  private final EMessageDigestAlgorithm m_eMDAlgo;
  private ZipWalkerSettings m_aZipSettings = new ZipWalkerSettings ();

  protected AsicReaderFactory (@NonNull final EMessageDigestAlgorithm eMDAlgo)
  {
    m_eMDAlgo = eMDAlgo;
  }

  /**
   * @return A copy of the limits for reading the container as ZIP archive (number of entries, total
   *         uncompressed size). Never <code>null</code>.
   * @since 4.1.1
   */
  @NonNull
  @ReturnsMutableCopy
  public final ZipWalkerSettings getZipSettings ()
  {
    return m_aZipSettings.getClone ();
  }

  /**
   * Set the limits for reading the container as ZIP archive (number of entries, total uncompressed
   * size).
   *
   * @param aZipSettings
   *        The settings to use. They are copied. May not be <code>null</code>.
   * @return this for chaining
   * @since 4.1.1
   */
  @NonNull
  public final AsicReaderFactory setZipSettings (@NonNull final ZipWalkerSettings aZipSettings)
  {
    ValueEnforcer.notNull (aZipSettings, "ZipSettings");
    m_aZipSettings = aZipSettings.getClone ();
    return this;
  }

  @NonNull
  public IAsicReader open (@NonNull final File aFile) throws IOException
  {
    return open (aFile.toPath ());
  }

  @NonNull
  public IAsicReader open (@NonNull final Path aFile) throws IOException
  {
    return open (Files.newInputStream (aFile));
  }

  @NonNull
  public IAsicReader open (@NonNull final InputStream aIS)
  {
    return new AsicReaderImpl (m_eMDAlgo, aIS, m_aZipSettings);
  }

  @NonNull
  public static AsicReaderFactory newFactory ()
  {
    return newFactory (EMessageDigestAlgorithm.SHA256);
  }

  @NonNull
  public static AsicReaderFactory newFactory (final EMessageDigestAlgorithm eMD)
  {
    return new AsicReaderFactory (eMD);
  }
}
