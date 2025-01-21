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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import javax.annotation.Nonnull;

public class AsicReaderFactory
{
  private final EMessageDigestAlgorithm m_eMDAlgo;

  protected AsicReaderFactory (@Nonnull final EMessageDigestAlgorithm eMDAlgo)
  {
    m_eMDAlgo = eMDAlgo;
  }

  @Nonnull
  public IAsicReader open (@Nonnull final File aFile) throws IOException
  {
    return open (aFile.toPath ());
  }

  @Nonnull
  public IAsicReader open (@Nonnull final Path aFile) throws IOException
  {
    return open (Files.newInputStream (aFile));
  }

  @Nonnull
  public IAsicReader open (@Nonnull final InputStream aIS)
  {
    return new AsicReaderImpl (m_eMDAlgo, aIS);
  }

  @Nonnull
  public static AsicReaderFactory newFactory ()
  {
    return newFactory (EMessageDigestAlgorithm.SHA256);
  }

  @Nonnull
  public static AsicReaderFactory newFactory (final EMessageDigestAlgorithm eMD)
  {
    return new AsicReaderFactory (eMD);
  }
}
