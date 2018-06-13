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

import java.io.IOException;
import java.io.OutputStream;

import javax.annotation.Nonnull;

public class XadesAsicWriter extends AbstractAsicWriter
{
  public XadesAsicWriter (@Nonnull final ESignatureMethod eSM,
                          @Nonnull final OutputStream aOS,
                          final boolean bCloseStreamOnSign) throws IOException
  {
    super (aOS, bCloseStreamOnSign, new XadesAsicManifest (eSM.getMessageDigestAlgorithm ()));
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
    m_aAsicOutputStream.writeZipEntry ("META-INF/signatures.xml", manifestBytes);
  }
}
