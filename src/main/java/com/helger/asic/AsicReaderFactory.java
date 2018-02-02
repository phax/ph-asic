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
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import javax.annotation.Nonnull;

public class AsicReaderFactory
{
  @Nonnull
  public static AsicReaderFactory newFactory ()
  {
    return newFactory (EMessageDigestAlgorithm.SHA256);
  }

  @Nonnull
  public static AsicReaderFactory newFactory (final ESignatureMethod signatureMethod)
  {
    return newFactory (signatureMethod.getMessageDigestAlgorithm ());
  }

  @Nonnull
  static AsicReaderFactory newFactory (final EMessageDigestAlgorithm messageDigestAlgorithm)
  {
    return new AsicReaderFactory (messageDigestAlgorithm);
  }

  private final EMessageDigestAlgorithm m_eMD;

  protected AsicReaderFactory (@Nonnull final EMessageDigestAlgorithm messageDigestAlgorithm)
  {
    m_eMD = messageDigestAlgorithm;
  }

  @Nonnull
  public IAsicReader open (@Nonnull final File file) throws IOException
  {
    return open (file.toPath ());
  }

  @Nonnull
  public IAsicReader open (@Nonnull final Path file) throws IOException
  {
    return open (Files.newInputStream (file));
  }

  @Nonnull
  public IAsicReader open (@Nonnull final InputStream inputStream)
  {
    return new AsicReaderImpl (m_eMD, inputStream);
  }
}
