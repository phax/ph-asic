/*
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018-2023 Philip Helger (www.helger.com)
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
import java.util.UUID;

import javax.annotation.Nonnull;

/**
 * Builds an ASiC-E Cades container using a variation of "builder pattern". This
 * class is not thread safe, as it indirectly holds a MessageDigest object.
 *
 * @author steinar Date: 02.07.15 Time: 12.09
 */
public class CadesAsicWriter extends AbstractAsicWriter
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
  public CadesAsicWriter (@Nonnull final OutputStream aOS,
                          final boolean bCloseStreamOnSign,
                          @Nonnull final EMessageDigestAlgorithm eMDAlgo,
                          final boolean bWriteOasisManifest) throws IOException
  {
    super (aOS, bCloseStreamOnSign, new CadesAsicManifest (eMDAlgo), bWriteOasisManifest);
  }

  @Override
  @Nonnull
  public final CadesAsicManifest getAsicManifest ()
  {
    return (CadesAsicManifest) super.getAsicManifest ();
  }

  @Override
  public IAsicWriter setRootEntryName (final String sName)
  {
    getAsicManifest ().setRootfileForEntry (sName);
    return this;
  }

  @Override
  protected void performSign (@Nonnull final SignatureHelper aSH) throws IOException
  {
    // Define signature filename containing UUID
    final String sSignatureFilename = "META-INF/" +
                                      AsicUtils.SIGNATURE_BASENAME +
                                      "-" +
                                      UUID.randomUUID ().toString () +
                                      ".p7s";

    // Adding signature file to asic manifest before actual signing
    getAsicManifest ().setSignature (sSignatureFilename, "application/x-pkcs7-signature");

    // Generates and writes manifest (META-INF/ASiCManifest.xml) to the zip
    // archive
    final byte [] aManifestBytes = getAsicManifest ().getAsBytes ();
    m_aAsicOutputStream.writeZipEntry ("META-INF/" + AsicUtils.ASIC_MANIFEST_BASENAME + ".xml", aManifestBytes);

    // Generates and writes signature (META-INF/signature-*.p7s) to the zip
    // archive
    final byte [] aSignatureBytes = aSH.signData (aManifestBytes, getAsicManifest ().getMessageDigestAlgorithm ());
    m_aAsicOutputStream.writeZipEntry (sSignatureFilename, aSignatureBytes);
  }
}
