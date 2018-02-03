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

import com.helger.commons.ValueEnforcer;

public class AsicVerifierFactory
{
  private final EMessageDigestAlgorithm m_eMessageDigestAlgorithm;

  public static AsicVerifierFactory newFactory ()
  {
    return newFactory (EMessageDigestAlgorithm.SHA256);
  }

  public static AsicVerifierFactory newFactory (final ESignatureMethod eSM)
  {
    return newFactory (eSM.getMessageDigestAlgorithm ());
  }

  static AsicVerifierFactory newFactory (final EMessageDigestAlgorithm eMDAlgorithm)
  {
    return new AsicVerifierFactory (eMDAlgorithm);
  }

  protected AsicVerifierFactory (@Nonnull final EMessageDigestAlgorithm eMDAlgo)
  {
    ValueEnforcer.notNull (eMDAlgo, "MDAlgo");
    m_eMessageDigestAlgorithm = eMDAlgo;
  }

  @Nonnull
  public AsicVerifier verify (final File file) throws IOException
  {
    return verify (file.toPath ());
  }

  @Nonnull
  public AsicVerifier verify (final Path file) throws IOException
  {
    return verify (Files.newInputStream (file));
  }

  @Nonnull
  public AsicVerifier verify (final InputStream inputStream) throws IOException
  {
    return new AsicVerifier (m_eMessageDigestAlgorithm, inputStream);
  }
}
