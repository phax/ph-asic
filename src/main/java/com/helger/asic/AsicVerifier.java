/*
 * Copyright (C) 2015-2017 difi (www.difi.no)
 * Copyright (C) 2018-2026 Philip Helger (www.helger.com)
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
import java.io.InputStream;

import org.jspecify.annotations.NonNull;

import com.helger.annotation.WillClose;
import com.helger.base.io.stream.NullOutputStream;
import com.helger.io.zip.ZipWalkerSettings;

public class AsicVerifier extends AbstractAsicReader
{
  protected AsicVerifier (@NonNull final EMessageDigestAlgorithm eMDAlgo,
                          @NonNull @WillClose final InputStream aIS) throws IOException
  {
    this (eMDAlgo, aIS, new ZipWalkerSettings ());
  }

  /**
   * Constructor. Reads and verifies the complete container.
   *
   * @param eMDAlgo
   *        The message digest algorithm to use. May not be <code>null</code>.
   * @param aIS
   *        The ASiC container to verify. Is closed. May not be <code>null</code>.
   * @param aZipSettings
   *        The limits for reading the container as ZIP archive. May not be <code>null</code>.
   * @throws IOException
   *         On read error, or if the container is not a ZIP archive or exceeds a limit
   * @since 4.1.1
   */
  protected AsicVerifier (@NonNull final EMessageDigestAlgorithm eMDAlgo,
                          @NonNull @WillClose final InputStream aIS,
                          @NonNull final ZipWalkerSettings aZipSettings) throws IOException
  {
    super (eMDAlgo, aIS, aZipSettings);

    try
    {
      while (getNextFile () != null)
        internalWriteFile (new NullOutputStream ());
    }
    finally
    {
      close ();
    }
  }
}
