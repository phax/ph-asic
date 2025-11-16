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

import com.helger.annotation.WillCloseWhenClosed;
import com.helger.base.enforce.ValueEnforcer;

public class AsicVerifierFactory
{
  private final EMessageDigestAlgorithm m_eMDAlgo;

  @NonNull
  public static AsicVerifierFactory newFactory ()
  {
    return newFactory (EMessageDigestAlgorithm.DEFAULT);
  }

  @NonNull
  public static AsicVerifierFactory newFactory (@NonNull final EMessageDigestAlgorithm eMDAlgo)
  {
    return new AsicVerifierFactory (eMDAlgo);
  }

  protected AsicVerifierFactory (@NonNull final EMessageDigestAlgorithm eMDAlgo)
  {
    ValueEnforcer.notNull (eMDAlgo, "MDAlgo");
    m_eMDAlgo = eMDAlgo;
  }

  @NonNull
  public AsicVerifier verify (@NonNull final File aFile) throws IOException
  {
    return verify (aFile.toPath ());
  }

  @NonNull
  public AsicVerifier verify (@NonNull final Path aFile) throws IOException
  {
    return verify (Files.newInputStream (aFile));
  }

  @NonNull
  public AsicVerifier verify (@NonNull @WillCloseWhenClosed final InputStream aIS) throws IOException
  {
    return new AsicVerifier (m_eMDAlgo, aIS);
  }
}
