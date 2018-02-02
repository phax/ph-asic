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

public class AsicVerifierFactory
{
  private final EMessageDigestAlgorithm m_eMessageDigestAlgorithm;

  public static AsicVerifierFactory newFactory ()
  {
    return newFactory (EMessageDigestAlgorithm.SHA256);
  }

  public static AsicVerifierFactory newFactory (final ESignatureMethod signatureMethod)
  {
    return newFactory (signatureMethod.getMessageDigestAlgorithm ());
  }

  static AsicVerifierFactory newFactory (final EMessageDigestAlgorithm messageDigestAlgorithm)
  {
    return new AsicVerifierFactory (messageDigestAlgorithm);
  }

  private AsicVerifierFactory (final EMessageDigestAlgorithm messageDigestAlgorithm)
  {
    this.m_eMessageDigestAlgorithm = messageDigestAlgorithm;
  }

  public AsicVerifier verify (final File file) throws IOException
  {
    return verify (file.toPath ());
  }

  public AsicVerifier verify (final Path file) throws IOException
  {
    return verify (Files.newInputStream (file));
  }

  public AsicVerifier verify (final InputStream inputStream) throws IOException
  {
    return new AsicVerifier (m_eMessageDigestAlgorithm, inputStream);
  }
}
