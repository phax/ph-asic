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

import java.io.IOException;
import java.io.OutputStream;

import javax.annotation.Nonnull;

public class XadesAsicWriter extends AbstractAsicWriter
{
  /**
   * Prepares creation of a new container.
   *
   * @param aOS
   *        Stream used to write container.
   * @param bCloseStreamOnSign
   *        close stream when this is signed
   * @param eMDAlgo
   *        Message Digest Algorithm
   * @param bWriteOasisManifest
   *        <code>true</code> if the OASIS OpenDocument Manifest XML should also
   *        be created.
   * @throws IOException
   *         on IO error
   */
  public XadesAsicWriter (@Nonnull final OutputStream aOS,
                          final boolean bCloseStreamOnSign,
                          @Nonnull final EMessageDigestAlgorithm eMDAlgo,
                          final boolean bWriteOasisManifest) throws IOException
  {
    super (aOS, bCloseStreamOnSign, new XadesAsicManifest (eMDAlgo), bWriteOasisManifest);
  }

  @Override
  @Nonnull
  public XadesAsicManifest getAsicManifest ()
  {
    return (XadesAsicManifest) super.getAsicManifest ();
  }

  @Override
  public IAsicWriter setRootEntryName (final String name)
  {
    throw new IllegalStateException ("ASiC-E XAdES does not support defining root file.");
  }

  @Override
  protected void performSign (@Nonnull final SignatureHelper aSH) throws IOException
  {
    // Generate and write manifest (META-INF/signatures.xml)
    final byte [] manifestBytes = getAsicManifest ().getAsBytes (aSH);
    m_aAsicOutputStream.writeZipEntry ("META-INF/" + AsicUtils.SIGNATURES_BASENAME + ".xml", manifestBytes);
  }
}
