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
import java.io.OutputStream;

import org.jspecify.annotations.NonNull;

import com.helger.annotation.WillCloseWhenClosed;
import com.helger.io.zip.ZipWalkerSettings;

public class AsicReaderImpl extends AbstractAsicReader implements IAsicReader
{
  protected AsicReaderImpl (@NonNull final EMessageDigestAlgorithm eMDAlgo,
                            @NonNull @WillCloseWhenClosed final InputStream aIS)
  {
    super (eMDAlgo, aIS);
  }

  /**
   * Constructor.
   *
   * @param eMDAlgo
   *        The message digest algorithm to use. May not be <code>null</code>.
   * @param aIS
   *        The ASiC container to read. May not be <code>null</code>.
   * @param aZipSettings
   *        The limits for reading the container as ZIP archive. May not be <code>null</code>.
   * @since 4.1.1
   */
  protected AsicReaderImpl (@NonNull final EMessageDigestAlgorithm eMDAlgo,
                            @NonNull @WillCloseWhenClosed final InputStream aIS,
                            @NonNull final ZipWalkerSettings aZipSettings)
  {
    super (eMDAlgo, aIS, aZipSettings);
  }

  @Override
  public void writeFile (@NonNull final OutputStream aOS) throws IOException
  {
    super.internalWriteFile (aOS);
  }

  @Override
  @NonNull
  public InputStream inputStream ()
  {
    return super.internalInputStream ();
  }
}
