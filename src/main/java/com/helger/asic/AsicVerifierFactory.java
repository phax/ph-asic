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

import com.helger.annotation.WillCloseWhenClosed;
import com.helger.base.enforce.ValueEnforcer;

import jakarta.annotation.Nonnull;

public class AsicVerifierFactory
{
  private final EMessageDigestAlgorithm m_eMDAlgo;

  @Nonnull
  public static AsicVerifierFactory newFactory ()
  {
    return newFactory (EMessageDigestAlgorithm.DEFAULT);
  }

  @Nonnull
  public static AsicVerifierFactory newFactory (@Nonnull final EMessageDigestAlgorithm eMDAlgo)
  {
    return new AsicVerifierFactory (eMDAlgo);
  }

  protected AsicVerifierFactory (@Nonnull final EMessageDigestAlgorithm eMDAlgo)
  {
    ValueEnforcer.notNull (eMDAlgo, "MDAlgo");
    m_eMDAlgo = eMDAlgo;
  }

  @Nonnull
  public AsicVerifier verify (@Nonnull final File aFile) throws IOException
  {
    return verify (aFile.toPath ());
  }

  @Nonnull
  public AsicVerifier verify (@Nonnull final Path aFile) throws IOException
  {
    return verify (Files.newInputStream (aFile));
  }

  @Nonnull
  public AsicVerifier verify (@Nonnull @WillCloseWhenClosed final InputStream aIS) throws IOException
  {
    return new AsicVerifier (m_eMDAlgo, aIS);
  }
}
