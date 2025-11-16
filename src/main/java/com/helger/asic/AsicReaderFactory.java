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

import org.jspecify.annotations.NonNull;

public class AsicReaderFactory
{
  private final EMessageDigestAlgorithm m_eMDAlgo;

  protected AsicReaderFactory (@NonNull final EMessageDigestAlgorithm eMDAlgo)
  {
    m_eMDAlgo = eMDAlgo;
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
    return new AsicReaderImpl (m_eMDAlgo, aIS);
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
